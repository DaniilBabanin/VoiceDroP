package com.voicedrop.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.voicedrop.crypto.AutoResetTrigger
import com.voicedrop.crypto.InvalidPayload
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.MessagePayload
import com.voicedrop.crypto.RatchetCryptoFailure
import com.voicedrop.crypto.RatchetDecryptAndPersist
import com.voicedrop.crypto.RatchetStatePersistence
import com.voicedrop.crypto.ReceiptInboundHandler
import com.voicedrop.crypto.ResetReceive
import com.voicedrop.crypto.ResetRetransmitJob
import com.voicedrop.crypto.WrapHmacMismatch
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * DR17.5 deframer + transmit hub.
 *
 * Inbound: [processFrame] is the single entry-point for delivered wire bytes. It
 *   1. [FrameCodec.decode]s — drops on structural failure;
 *   2. admits via [IngestRateLimiter] (DR10) — silently drops on bucket empty;
 *   3. routes on [FrameCodec.FRAME_KIND_DATA] / `KIND_RECEIPT` to
 *      [RatchetDecryptAndPersist.receive] with an inner-plaintext dispatcher
 *      that handles VOICE / HELLO / DELETE / unknown per dr17.5;
 *   4. routes on [FrameCodec.FRAME_KIND_RESET] to [ResetReceive.onResetFrame].
 *
 * Outbound: [transmit] is crypto-free — the wire bytes are already sealed by
 * [com.voicedrop.crypto.RatchetEncryptAndSend]. Just picks a path (existing
 * connection, LAN, STUN/P2P, relay). On all-paths-fail it starts an
 * active-backoff retry loop that drives [PendingOutboxReplay.replayAll] until
 * the contact's outbox empties or the per-kind give-up cap fires.
 *
 * Replay triggers:
 *   - [NetworkCallback.onAvailable] → [PendingOutboxReplay.replayAll] +
 *     [ResetRetransmitJob.onConnectivityAvailable].
 *   - LAN discovery / signaling presence: peer appearance → `replayAll()`.
 *   - [onAppForeground] → `replayAll()`.
 *   - Active backoff: per tick → `replayAll()`, exit when the contact's outbox
 *     is empty.
 */
class ConnectionManager(
    private val context: Context,
    private val repository: MessageRepository,
    private val keyManager: KeyManager,
    private val workerUrl: String,
    private val db: AppDatabase,
    private val ratchetReceiver: RatchetDecryptAndPersist,
    private val receiptInboundHandler: ReceiptInboundHandler,
    private val resetReceive: ResetReceive,
    private val autoResetTrigger: AutoResetTrigger,
    private val ingestRateLimiter: IngestRateLimiter,
    private val pendingOutboxReplay: PendingOutboxReplay,
    private val resetRetransmitJob: ResetRetransmitJob,
    private val relayFallbackEnabled: Boolean = true
) {
    private val ownFingerprint = keyManager.getFingerprint()
    private val notificationHelper = NotificationHelper(context)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()
    private val connections = mutableMapOf<String, PeerConnection>()
    private val connectionTransports = mutableMapOf<String, TransportType>()
    private val transmitMutexes = mutableMapOf<String, Mutex>()
    private val backoffJobs = mutableMapOf<String, Job>()
    private val connector = PeerConnector()
    private val stunClient = StunClient()

    // LAN peers seen via NSD — keyed by fingerprint
    private val lanPeers = mutableMapOf<String, LanPeer>()

    // Persistent signaling connections for presence (one per contact)
    private val signalingClients = mutableMapOf<String, SignalingClient>()

    private var lanDiscovery: LanDiscovery? = null
    private var listenPort: Int = 0
    private var listenServerSocket: ServerSocket? = null

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network available — replaying outbox + reset retransmits")
            scope.launch {
                pendingOutboxReplay.replayAll()
                resetRetransmitJob.onConnectivityAvailable()
            }
        }
    }

    fun start() {
        Log.i(TAG, "start: ownFp=${ownFingerprint.take(8)} workerUrl=${workerUrl.ifBlank { "<blank>" }}")
        connectivityManager.registerNetworkCallback(
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build(),
            networkCallback
        )

        listenPort = (10000..60000).random()
        Log.i(TAG, "Listening on port $listenPort")
        scope.launch { startListening() }
        scope.launch { startLanDiscovery() }
        if (workerUrl.isNotBlank()) scope.launch { startSignalingPresence() }
    }

    fun stop() {
        Log.i(TAG, "stop")
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        lanDiscovery?.stop()
        signalingClients.values.forEach { it.disconnect() }
        signalingClients.clear()
        listenServerSocket?.close()
        connections.values.forEach { it.close() }
        scope.cancel()
    }

    fun onAppForeground() {
        Log.i(TAG, "App foregrounded — replaying outbox")
        scope.launch { pendingOutboxReplay.replayAll() }
    }

    /**
     * Transmit pre-sealed wire bytes to [contactId]. Tries existing connection
     * → LAN → STUN/P2P → relay in order. On all-paths-fail kicks off an
     * active-backoff replay loop and returns [TransportType.UNKNOWN].
     *
     * Crypto-free: the bytes come from [com.voicedrop.crypto.RatchetEncryptAndSend]
     * (or [com.voicedrop.crypto.ResetReceive]) which has already inserted a row
     * into `pending_outbound_frames` — this method does NOT enqueue v1 outbox
     * actions or attempt retries beyond starting the backoff job. Per-kind
     * give-up caps live in [PendingOutboxReplay].
     */
    suspend fun transmit(contactId: String, frame: ByteArray): TransportType {
        val fp = contactId.take(8)
        Log.i(TAG, "transmit fp=$fp frameBytes=${frame.size}")
        val mutex = transmitMutexes.getOrPut(contactId) { Mutex() }
        return mutex.withLock {
            val transport = when {
                tryExistingConnection(contactId, frame) ->
                    connectionTransports[contactId] ?: TransportType.UNKNOWN
                tryLanConnect(contactId, frame) -> TransportType.LAN
                tryStunConnect(contactId, frame) -> TransportType.P2P
                relayFallbackEnabled && tryRelayUpload(contactId, frame) -> TransportType.RELAY
                else -> {
                    Log.w(TAG, "transmit fp=$fp: all paths failed — starting backoff replay")
                    startActiveBackoff(contactId)
                    TransportType.UNKNOWN
                }
            }
            if (transport != TransportType.UNKNOWN) {
                Log.i(TAG, "transmit fp=$fp: delivered via transport=$transport")
            }
            transport
        }
    }

    private suspend fun tryExistingConnection(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        val conn = connections[contactId]
        if (conn == null) {
            if (VERBOSE) Log.d(TAG, "path1 fp=$fp: no existing connection")
            return false
        }
        return if (conn.isAlive) {
            try {
                conn.send(frame)
                Log.i(TAG, "path1 fp=$fp: sent via existing connection (transport=${connectionTransports[contactId]})")
                true
            } catch (e: Exception) {
                Log.w(TAG, "path1 fp=$fp: existing connection dead — ${e.message}")
                connections.remove(contactId)
                connectionTransports.remove(contactId)
                false
            }
        } else {
            if (VERBOSE) Log.d(TAG, "path1 fp=$fp: existing connection not alive")
            connections.remove(contactId)
            connectionTransports.remove(contactId)
            false
        }
    }

    private suspend fun tryLanConnect(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        val peer = lanPeers[contactId]
        if (peer == null) {
            if (VERBOSE) Log.d(TAG, "path2 fp=$fp: no LAN peer cached")
            return false
        }
        Log.i(TAG, "path2 fp=$fp: LAN peer at ${peer.host}:${peer.port}")
        return connectAndSend(contactId, peer.host, peer.port, frame, TransportType.LAN)
    }

    private suspend fun tryStunConnect(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        if (workerUrl.isBlank()) {
            Log.d(TAG, "path3 fp=$fp: skipped (no signaling URL)")
            return false
        }

        Log.d(TAG, "path3 fp=$fp: getting STUN address")
        val stunResult = stunClient.getPublicAddress()
        val ourIp = stunResult?.address?.hostAddress ?: run {
            Log.w(TAG, "path3 fp=$fp: STUN failed — no public address")
            return false
        }

        val ourStunStr = "$ourIp:$listenPort"
        val roomKey = deriveRoomKey(ownFingerprint, contactId)
        Log.i(TAG, "path3 fp=$fp: STUN=$ourStunStr room=${roomKey.take(16)}…")

        val peerHello: Signal.PeerHello? = try {
            coroutineScope {
                val sendClient = SignalingClient(workerUrl, ownFingerprint)
                val collector = async {
                    withTimeoutOrNull(15_000L) {
                        var found: Signal.PeerHello? = null
                        sendClient.signals.collect { signal ->
                            when (signal) {
                                is Signal.PeerHello -> if (signal.fingerprint == contactId) {
                                    found = signal
                                    sendClient.disconnect()
                                }
                                is Signal.OutboxPing -> Log.d(TAG, "path3 fp=$fp: outbox_ping — skipped (presence handles relay)")
                                is Signal.RelayFrame -> Log.d(TAG, "path3 fp=$fp: relay_frame — skipped (presence handles relay)")
                                else -> {}
                            }
                        }
                        found
                    }
                }
                val connected = sendClient.connect(roomKey, ourStunStr)
                val hello = if (connected) collector.await() else null
                sendClient.disconnect()
                hello
            }
        } catch (e: Exception) {
            Log.w(TAG, "path3 fp=$fp: signaling error — ${e.message}")
            return false
        }

        if (peerHello == null) {
            Log.w(TAG, "path3 fp=$fp: peer not in signaling room within 15s")
            return false
        }

        Log.i(TAG, "path3 fp=$fp: peer at ${peerHello.stunAddr} — connecting")
        val parts = peerHello.stunAddr.split(":")
        if (parts.size != 2) {
            Log.w(TAG, "path3 fp=$fp: malformed stunAddr=${peerHello.stunAddr}")
            return false
        }
        val peerHost = parts[0]
        val peerPort = parts[1].toIntOrNull() ?: run {
            Log.w(TAG, "path3 fp=$fp: invalid port in stunAddr")
            return false
        }

        val socket = connector.connectDirect(peerHost, peerPort)
            ?: connector.holePunch(listenPort, InetSocketAddress(peerHost, peerPort))

        if (socket == null) {
            Log.w(TAG, "path3 fp=$fp: direct and hole-punch both failed to $peerHost:$peerPort")
            return false
        }

        val conn = PeerConnection(socket)
        connections[contactId] = conn
        connectionTransports[contactId] = TransportType.P2P
        scope.launch { receiveLoop(contactId, conn) }
        conn.send(frame)
        Log.i(TAG, "path3 fp=$fp: sent ${frame.size} bytes via signaling/WAN path")
        return true
    }

    private suspend fun connectAndSend(
        contactId: String,
        host: String,
        port: Int,
        frame: ByteArray,
        transport: TransportType
    ): Boolean {
        val fp = contactId.take(8)
        return try {
            Log.d(TAG, "connectAndSend fp=$fp: connecting to $host:$port transport=$transport")
            val socket = connector.connectDirect(host, port)
            if (socket == null) {
                Log.w(TAG, "connectAndSend fp=$fp: timed out")
                return false
            }
            val conn = PeerConnection(socket)
            connections[contactId] = conn
            connectionTransports[contactId] = transport
            scope.launch { receiveLoop(contactId, conn) }
            conn.send(frame)
            Log.i(TAG, "connectAndSend fp=$fp: sent ${frame.size} bytes")
            true
        } catch (e: Exception) {
            Log.w(TAG, "connectAndSend fp=$fp: failed — ${e.message}")
            false
        }
    }

    /**
     * Active backoff: walk a fixed delay schedule, replay the outbox on each
     * tick, exit early when this contact's outbox is empty. The persisted
     * per-kind give-up cap in [PendingOutboxReplay] is the real upper bound
     * here — this loop only adds urgency on top of the [DEFAULT_BACKOFF_MS]
     * schedule.
     */
    private fun startActiveBackoff(contactId: String) {
        val fp = contactId.take(8)
        backoffJobs[contactId]?.cancel()
        backoffJobs[contactId] = scope.launch {
            val delays = DEFAULT_BACKOFF_MS
            var attempt = 0
            while (attempt < BACKOFF_MAX_ATTEMPTS) {
                val delayMs = delays.getOrElse(attempt) { delays.last() }
                if (VERBOSE) Log.d(TAG, "backoff fp=$fp: attempt $attempt — waiting ${delayMs / 1000}s")
                delay(delayMs)
                if (VERBOSE) Log.d(TAG, "backoff fp=$fp: attempt $attempt — retrying")
                pendingOutboxReplay.replayAll()
                val remaining = db.pendingOutboundFrameDao().countForContact(contactId)
                if (remaining == 0) {
                    Log.i(TAG, "backoff fp=$fp: outbox empty after attempt $attempt")
                    break
                }
                attempt++
            }
            if (attempt >= BACKOFF_MAX_ATTEMPTS) {
                Log.w(TAG, "backoff fp=$fp: max attempts reached (give-up caps still apply per row)")
            }
        }
    }

    private suspend fun receiveLoop(contactId: String, conn: PeerConnection) {
        Log.d(TAG, "receiveLoop fp=${contactId.take(8)}: started")
        conn.receiveFlow().collect { frame ->
            val transport = connectionTransports[contactId] ?: TransportType.UNKNOWN
            Log.i(TAG, "receiveLoop fp=${contactId.take(8)}: received ${frame.size} bytes transport=$transport")
            processFrame(frame, transport)
        }
        Log.d(TAG, "receiveLoop fp=${contactId.take(8)}: ended")
    }

    private suspend fun startListening() {
        Log.i(TAG, "startListening: binding to port $listenPort")
        val server = try {
            ServerSocket(listenPort)
        } catch (e: Exception) {
            Log.e(TAG, "startListening: failed to bind port $listenPort — ${e.message}")
            return
        }
        listenServerSocket = server
        Log.i(TAG, "startListening: accepting on port $listenPort")
        while (true) {
            try {
                val socket = server.accept()
                Log.i(TAG, "startListening: incoming from ${socket.inetAddress.hostAddress}")
                scope.launch { handleIncoming(socket) }
            } catch (e: Exception) {
                Log.d(TAG, "startListening: server socket closed — ${e.message}")
                break
            }
        }
    }

    private fun handleIncoming(socket: Socket) {
        val addr = socket.inetAddress.hostAddress
        val transport = if (socket.inetAddress.isSiteLocalAddress ||
            socket.inetAddress.isLinkLocalAddress ||
            socket.inetAddress.isLoopbackAddress
        ) TransportType.LAN else TransportType.P2P
        Log.i(TAG, "handleIncoming: from $addr transport=$transport")
        val conn = PeerConnection(socket)
        scope.launch {
            conn.receiveFlow().collect { frame ->
                Log.i(TAG, "handleIncoming: received ${frame.size} bytes from $addr")
                processFrame(frame, transport)
            }
            Log.d(TAG, "handleIncoming: flow ended for $addr")
        }
    }

    /**
     * Single entry-point for delivered wire bytes. See class kdoc for the
     * ordered decode → admit → route pipeline.
     */
    private suspend fun processFrame(bytes: ByteArray, transport: TransportType = TransportType.UNKNOWN) {
        val decoded = when (val r = FrameCodec.decode(bytes)) {
            is FrameCodec.DecodeResult.Ok -> r.frame
            is FrameCodec.DecodeResult.Drop -> {
                Log.w(TAG, "processFrame: decode dropped reason=${r.reason}")
                return
            }
        }
        if (!ingestRateLimiter.tryAdmit(decoded.senderFp, decoded.recipFp)) {
            // IngestRateLimiter aggregates drop telemetry; nothing to do here.
            return
        }

        val senderHex = bytesToHex(decoded.senderFp)
        val contact = repository.getContact(senderHex) ?: run {
            Log.w(TAG, "processFrame: unknown sender ${senderHex.take(8)}")
            return
        }

        when (decoded.kind) {
            FrameCodec.FRAME_KIND_DATA, FrameCodec.FRAME_KIND_RECEIPT ->
                handleDataOrReceipt(decoded, contact, transport)
            FrameCodec.FRAME_KIND_RESET ->
                resetReceive.onResetFrame(contact.id, decoded)
        }
    }

    private suspend fun handleDataOrReceipt(
        frame: FrameCodec.DecodedFrame,
        contact: ContactEntity,
        transport: TransportType
    ) {
        val result = try {
            ratchetReceiver.receive(contact.id, frame) { plaintext, _, uuidBytes, ts ->
                dispatchPlaintextInsideTxn(plaintext, uuidBytes, ts, contact, transport)
            }
        } catch (e: RatchetCryptoFailure) {
            // Counter bump is owned by RatchetDecryptAndPersist's outside-txn UPDATE
            // (dr8 §8.2); the soft-prompt banner observes it (dr14, surfaced by W6).
            Log.w(TAG, "processFrame: AEAD failed for ${contact.id.take(8)}")
            return
        } catch (e: RatchetStatePersistence.RatchetStateCorrupt) {
            Log.e(TAG, "processFrame: structural corruption for ${contact.id.take(8)} — firing auto-reset evaluator")
            autoResetTrigger.onStructuralCorruption(contact.id, e)
            return
        } catch (e: WrapHmacMismatch) {
            // CRYPTO_TAMPER per AutoResetTrigger.classify — does not auto-reset.
            // UI will surface a "possible tamper" banner once the reader observes the contact's state.
            Log.e(TAG, "processFrame: wrap-binding tamper for ${contact.id.take(8)}")
            return
        } catch (e: Throwable) {
            Log.e(TAG, "processFrame: unexpected decrypt error for ${contact.id.take(8)} — ${e::class.simpleName}: ${e.message}")
            return
        }

        when (result) {
            is RatchetDecryptAndPersist.Result.Delivered -> postDeliveredSideEffects(result, contact)
            is RatchetDecryptAndPersist.Result.ReceiptDecrypted ->
                receiptInboundHandler.onReceiptDecrypted(contact.id, result.ackedUuid)
            is RatchetDecryptAndPersist.Result.DuplicateData -> {
                // Ratchet re-enqueued a fresh RECEIPT inside the txn; nothing to do here.
            }
            is RatchetDecryptAndPersist.Result.DuplicateReceipt -> {
                // Vanishingly rare; benign no-op.
            }
        }
    }

    /**
     * Inner-plaintext dispatcher — runs INSIDE the ratchet receive txn so VOICE
     * row-insert / DELETE row-delete are atomic with state advance + RECEIPT
     * enqueue (per dr17.5 §"Receive-side dispatch"). File-system effects
     * (.opus write for VOICE, .opus delete for DELETE) and notifications are
     * handled by [postDeliveredSideEffects] AFTER the txn commits — best-effort
     * per dr17.5 (no replay if app crashes between txn commit and file delete).
     */
    private fun dispatchPlaintextInsideTxn(
        plaintext: ByteArray,
        frameUuidBytes: ByteArray,
        wireTimestampMs: Long,
        contact: ContactEntity,
        transport: TransportType
    ): MessageEntity? {
        val parsed = try {
            MessagePayload.parse(plaintext)
        } catch (e: InvalidPayload) {
            // Malformed inner plaintext after AEAD success — extremely rare;
            // implies a peer running a broken codec. Forward-compat contract is
            // for UNKNOWN kinds only; truly malformed payloads still get a
            // silent drop (RECEIPT already enqueued upstream). Throwing here
            // would roll back the txn and jam the sender's outbox.
            Log.w(TAG, "dispatchPlaintext: malformed payload from ${contact.id.take(8)} — ${e.message}")
            return null
        }
        return when (parsed) {
            is MessagePayload.Parsed.Voice -> buildVoiceEntityInsideTxn(parsed, frameUuidBytes, wireTimestampMs, contact, transport)
            is MessagePayload.Parsed.Hello -> {
                Log.i(TAG, "HELLO from ${contact.id.take(8)} — bootstrap sentinel; RECEIPT will clear sender's outbox")
                null
            }
            is MessagePayload.Parsed.Delete -> {
                val targetUuidStr = parsed.targetUuid.toString()
                val deleted = db.openHelper.writableDatabase
                    .delete("messages", "uuid = ?", arrayOf(targetUuidStr))
                Log.i(TAG, "DELETE from ${contact.id.take(8)} target=${targetUuidStr.take(8)} rowsDeleted=$deleted")
                null
            }
            is MessagePayload.Parsed.Unknown -> {
                // Forward-compat contract: RECEIPT will still go out (the ratchet
                // path enqueues it before the callback fires); we silently drop
                // the payload. v1.3+ kinds land here on v1.2 devices.
                Log.i(TAG, "unknown kind=${parsed.kind} bodyLen=${parsed.bodyLen} from ${contact.id.take(8)} — dropping silently per forward-compat contract")
                null
            }
        }
    }

    private fun buildVoiceEntityInsideTxn(
        voice: MessagePayload.Parsed.Voice,
        frameUuidBytes: ByteArray,
        wireTimestampMs: Long,
        contact: ContactEntity,
        transport: TransportType
    ): MessageEntity {
        val uuidStr = uuidBytesToUuidString(frameUuidBytes)
        val messagesDir = File(context.filesDir, "messages").apply { mkdirs() }
        val opusFile = File(messagesDir, "$uuidStr.opus")
        // Plaintext audio at rest (dr17.5 decision 2b — trusts Android FS encryption).
        // Writing inside the txn extends the txn by FS-IO time; tolerable for the
        // VOICE rate and worth it for the atomicity with state advance.
        opusFile.writeBytes(voice.opusBytes)
        // ~150–600 ms opus decode inside the receive txn — this dominates txn
        // duration. See computePeaksFromOpus docstring for the tradeoff vs.
        // hoisting + Phase-F-style lazy backfill.
        val peaks = computePeaksFromOpus(voice.opusBytes)
        val now = System.currentTimeMillis()
        return MessageEntity(
            uuid = uuidStr,
            contactId = contact.id,
            direction = MessageEntity.DIRECTION_INBOUND,
            state = MessageEntity.STATE_DELIVERED,
            transport = transport,
            encryptedFilePath = opusFile.absolutePath,
            durationMs = voice.durationMs,
            deleteAfterMs = voice.deleteAfterMs,
            scheduledDeleteAt = if (voice.deleteAfterMs > 0) now + voice.deleteAfterMs else 0L,
            transcription = null,
            waveformPeaks = peaks,
            createdAt = wireTimestampMs,
            sentAt = 0L,
            deliveredAt = now
        )
    }

    private fun postDeliveredSideEffects(
        result: RatchetDecryptAndPersist.Result.Delivered,
        contact: ContactEntity
    ) {
        val parsed = try {
            MessagePayload.parse(result.plaintext)
        } catch (_: InvalidPayload) {
            return
        }
        when (parsed) {
            is MessagePayload.Parsed.Voice -> {
                // The txn already wrote the .opus file and inserted the row.
                val uuidStr = uuidHexToUuidString(result.messageUuidHex)
                notificationHelper.notifyIncoming(contact, uuidStr, parsed.durationMs)
            }
            is MessagePayload.Parsed.Delete -> {
                // Row was deleted in-txn; clear the audio file + cancel any active
                // notification. Best-effort.
                val targetUuidStr = parsed.targetUuid.toString()
                val opusFile = File(context.filesDir, "messages/$targetUuidStr.opus")
                if (opusFile.exists()) opusFile.delete()
                notificationHelper.cancelNotification(targetUuidStr.hashCode())
            }
            else -> { /* HELLO, Unknown — nothing to do */ }
        }
    }

    private suspend fun startLanDiscovery() {
        Log.i(TAG, "startLanDiscovery: registering _voicedrop._tcp on port $listenPort")
        lanDiscovery = LanDiscovery(context, ownFingerprint)
        lanDiscovery?.start(listenPort)
        lanDiscovery?.discoveredPeers?.collect { peer ->
            Log.i(TAG, "LAN: fp=${peer.fingerprint.take(8)} at ${peer.host}:${peer.port}")
            lanPeers[peer.fingerprint] = peer

            if (lanDiscovery!!.shouldInitiate(peer.fingerprint)) {
                Log.d(TAG, "LAN: we initiate to fp=${peer.fingerprint.take(8)} — replaying outbox")
                pendingOutboxReplay.replayAll()
            } else {
                Log.d(TAG, "LAN: peer fp=${peer.fingerprint.take(8)} initiates — we listen")
            }
        }
    }

    private suspend fun startSignalingPresence() {
        Log.i(TAG, "presence: starting (workerUrl=${workerUrl.take(40)})")

        val presenceJobs = mutableMapOf<String, Job>()
        try {
            repository.getAllContacts().collect { contacts ->
                val currentIds = contacts.map { it.id }.toSet()

                presenceJobs.keys.toList().forEach { id ->
                    if (id !in currentIds) {
                        presenceJobs.remove(id)?.cancel()
                        signalingClients.remove(id)?.disconnect()
                    }
                }

                if (contacts.isEmpty()) {
                    Log.d(TAG, "presence: no contacts")
                    return@collect
                }

                for (contact in contacts) {
                    if (contact.id in presenceJobs) continue
                    val roomKey = deriveRoomKey(ownFingerprint, contact.id)
                    Log.i(TAG, "presence: maintaining ${presenceJobs.size + 1} room(s)")
                    presenceJobs[contact.id] = scope.launch {
                        var backoffMs = 3_000L
                        while (true) {
                            val stunResult = stunClient.getPublicAddress()
                            val addr = "${stunResult?.address?.hostAddress ?: "0.0.0.0"}:$listenPort"
                            Log.i(TAG, "presence: connecting fp=${contact.id.take(8)} addr=$addr")

                            val client = SignalingClient(workerUrl, ownFingerprint)
                            signalingClients[contact.id] = client
                            client.connect(roomKey, addr)

                            try {
                                client.signals.collect { signal ->
                                    when (signal) {
                                        is Signal.PeerHello -> {
                                            Log.i(TAG, "presence: fp=${contact.id.take(8)} appeared at ${signal.stunAddr} — replaying outbox")
                                            backoffMs = 3_000L
                                            pendingOutboxReplay.replayAll()
                                        }
                                        is Signal.Presence -> Log.d(TAG, "presence: peer fp=${contact.id.take(8)} online=${signal.online}")
                                        is Signal.OutboxPing -> {
                                            if (!relayFallbackEnabled) {
                                                Log.d(TAG, "presence: outbox_ping fp=${contact.id.take(8)} ignored (relay fallback disabled)")
                                            } else {
                                                Log.i(TAG, "presence: outbox_ping fp=${contact.id.take(8)} count=${signal.count}")
                                                pullAndDeliverRelay(contact.id, roomKey)
                                            }
                                        }
                                        is Signal.RelayFrame -> {
                                            if (!relayFallbackEnabled) {
                                                Log.d(TAG, "presence: relay_frame fp=${contact.id.take(8)} ignored (relay fallback disabled)")
                                            } else {
                                                try {
                                                    val bytes = android.util.Base64.decode(signal.data, android.util.Base64.NO_WRAP)
                                                    Log.i(TAG, "presence: relay_frame fp=${contact.id.take(8)} size=${bytes.size}")
                                                    processFrame(bytes, TransportType.RELAY)
                                                } catch (e: Exception) {
                                                    Log.w(TAG, "presence: relay_frame error fp=${contact.id.take(8)} — ${e.message}")
                                                }
                                            }
                                        }
                                        else -> {}
                                    }
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "presence: collect error fp=${contact.id.take(8)}: ${e.message}")
                            }

                            if (VERBOSE) Log.d(TAG, "presence: disconnected fp=${contact.id.take(8)}, reconnecting in ${backoffMs}ms")
                            client.disconnect()
                            delay(backoffMs)
                            backoffMs = minOf(backoffMs * 2, 60_000L)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "presence: contacts flow error — ${e.message}")
        }
    }

    private suspend fun pullAndDeliverRelay(contactId: String, roomKey: String) {
        val fp = contactId.take(8)
        if (!relayFallbackEnabled) {
            Log.d(TAG, "presence: pull skipped fp=$fp (relay fallback disabled)")
            return
        }
        if (workerUrl.isBlank()) return
        try {
            val url = derivePullUrl(roomKey)
            val request = Request.Builder().url(url).get().build()
            val responseBody = httpClient.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) {
                    Log.w(TAG, "presence: pull failed fp=$fp code=${resp.code}")
                    return
                }
                resp.body?.string() ?: return
            }
            val obj = Json.parseToJsonElement(responseBody) as? JsonObject ?: return
            val frames = obj["frames"]?.jsonArray ?: return
            Log.i(TAG, "presence: pull fp=$fp — ${frames.size} frame(s)")
            for (frameEl in frames) {
                try {
                    val base64 = frameEl.jsonPrimitive.content
                    val bytes = android.util.Base64.decode(base64, android.util.Base64.NO_WRAP)
                    Log.i(TAG, "presence: relay_frame fp=$fp size=${bytes.size}")
                    processFrame(bytes, TransportType.RELAY)
                } catch (e: Exception) {
                    Log.w(TAG, "presence: relay_frame error fp=$fp — ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "presence: pull error fp=$fp — ${e.message}")
        }
    }

    private fun derivePullUrl(roomKey: String): String {
        val scheme = if (workerUrl.startsWith("wss://")) "https" else "http"
        val host = workerUrl
            .removePrefix("wss://")
            .removePrefix("ws://")
            .substringBefore("/")
        return "$scheme://$host/pull/$roomKey/$ownFingerprint"
    }

    private suspend fun tryRelayUpload(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        if (!relayFallbackEnabled) {
            Log.d(TAG, "relay fp=$fp: skipped (relay fallback disabled)")
            return false
        }
        if (workerUrl.isBlank()) return false
        val url = deriveRelayUrl(contactId)
        Log.d(TAG, "relay fp=$fp: uploading ${frame.size} bytes")
        return try {
            val body = frame.toRequestBody("application/octet-stream".toMediaTypeOrNull())
            val request = Request.Builder().url(url).post(body).build()
            httpClient.newCall(request).execute().use { response ->
                response.isSuccessful.also {
                    if (it) Log.i(TAG, "relay fp=$fp: uploaded")
                    else Log.w(TAG, "relay fp=$fp: upload failed ${response.code}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "relay fp=$fp: upload error — ${e.message}")
            false
        }
    }

    private fun deriveRelayUrl(recipientFp: String): String {
        val scheme = if (workerUrl.startsWith("wss://")) "https" else "http"
        val host = workerUrl
            .removePrefix("wss://")
            .removePrefix("ws://")
            .substringBefore("/")
        return "$scheme://$host/relay/$ownFingerprint/$recipientFp"
    }

    private fun deriveRoomKey(fp1: String, fp2: String): String {
        val sorted = listOf(fp1, fp2).sorted()
        return sorted[0] + sorted[1]
    }

    companion object {
        private const val TAG = "VoiceDrop/Net"
        private const val VERBOSE = true
        private const val BACKOFF_MAX_ATTEMPTS = 20
        private val DEFAULT_BACKOFF_MS = listOf(5_000L, 10_000L, 20_000L, 40_000L, 60_000L)

        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        private fun bytesToHex(b: ByteArray): String {
            val sb = StringBuilder(b.size * 2)
            for (x in b) {
                val v = x.toInt() and 0xff
                sb.append(HEX_DIGITS[v ushr 4]); sb.append(HEX_DIGITS[v and 0x0f])
            }
            return sb.toString()
        }

        /** 16-byte UUID bytes → standard dashed UUID string (matches `UUID.toString()`). */
        private fun uuidBytesToUuidString(bytes: ByteArray): String {
            require(bytes.size == 16) { "uuid bytes must be 16" }
            val bb = java.nio.ByteBuffer.wrap(bytes)
            return java.util.UUID(bb.long, bb.long).toString()
        }

        /** 32-char undashed hex (from FrameCodec) → standard dashed UUID string. */
        private fun uuidHexToUuidString(hex: String): String {
            require(hex.length == 32) { "uuid hex must be 32 chars" }
            val bytes = ByteArray(16) {
                val hi = Character.digit(hex[it * 2], 16)
                val lo = Character.digit(hex[it * 2 + 1], 16)
                ((hi shl 4) or lo).toByte()
            }
            return uuidBytesToUuidString(bytes)
        }
    }
}

/**
 * Decode the framed opus blob and run it through [com.voicedrop.audio.PeakAccumulator]
 * to produce the 80-byte waveform peaks for an inbound message. Same accumulator
 * the record path uses, so receive-side peaks match record-side peaks for
 * identical audio. Runs inside the receive txn — see caller comment.
 *
 * Frame format: repeated `[4-byte little-endian length N][N bytes opus packet]`
 * as written by `AudioRecorder.recordLoop`. Malformed length prefixes truncate
 * the waveform rather than crash. Per-packet decode failures propagate out and
 * roll the txn back (existing receive-side semantics).
 */
private fun computePeaksFromOpus(opus: ByteArray): ByteArray {
    // Defaults to 16kHz mono — matches AudioRecorder.recordLoop's encoder config.
    val decoder = com.voicedrop.audio.OpusDecoder()
    try {
        val acc = com.voicedrop.audio.PeakAccumulator()
        val input = java.io.ByteArrayInputStream(opus)
        val lenBuf = ByteArray(4)
        while (input.available() > 0) {
            if (input.read(lenBuf) != 4) break
            val n = java.nio.ByteBuffer.wrap(lenBuf).order(java.nio.ByteOrder.LITTLE_ENDIAN).int
            if (n <= 0 || n > 65536) break
            val packet = ByteArray(n)
            if (input.read(packet) != n) break
            val pcm = decoder.decode(packet)
            acc.feed(pcm, pcm.size)
        }
        return acc.build()
    } finally {
        decoder.release()
    }
}
