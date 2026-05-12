package com.voicedrop.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.voicedrop.crypto.ContactKey
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.MessageCrypto
import com.voicedrop.crypto.MessageType
import com.voicedrop.crypto.ParsedFrame
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import com.voicedrop.storage.PendingActionEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit

class ConnectionManager(
    private val context: Context,
    private val repository: MessageRepository,
    private val keyManager: KeyManager,
    private val workerUrl: String
) {
    private val ownFingerprint = keyManager.getFingerprint()
    private val notificationHelper = NotificationHelper(context)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()
    private val connections = mutableMapOf<String, PeerConnection>()
    private val mutexes = mutableMapOf<String, Mutex>()
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
            Log.i(TAG, "Network available — flushing all outboxes")
            scope.launch { flushAllOutboxes() }
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
        Log.i(TAG, "App foregrounded — flushing all outboxes")
        scope.launch { flushAllOutboxes() }
    }

    suspend fun sendToContact(contactId: String, frame: ByteArray) {
        val fp = contactId.take(8)
        Log.i(TAG, "sendToContact fp=$fp frameBytes=${frame.size}")
        val mutex = mutexes.getOrPut(contactId) { Mutex() }
        mutex.withLock {
            val sent = tryExistingConnection(contactId, frame)
                || tryLanConnect(contactId, frame)
                || tryStunConnect(contactId, frame)
                || tryRelayUpload(contactId, frame)

            if (sent) {
                Log.i(TAG, "sendToContact fp=$fp: delivered")
            } else {
                Log.w(TAG, "sendToContact fp=$fp: all paths failed — queuing outbox, starting backoff")
                enqueueOutbox(contactId, frame)
                startActiveBackoff(contactId)
            }
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
                Log.i(TAG, "path1 fp=$fp: sent via existing connection")
                true
            } catch (e: Exception) {
                Log.w(TAG, "path1 fp=$fp: existing connection dead — ${e.message}")
                connections.remove(contactId)
                false
            }
        } else {
            if (VERBOSE) Log.d(TAG, "path1 fp=$fp: existing connection not alive")
            connections.remove(contactId)
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
        return connectAndSend(contactId, peer.host, peer.port, frame)
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

        // Use our TCP listen port with the STUN-resolved public IP
        val ourStunStr = "$ourIp:$listenPort"
        val roomKey = deriveRoomKey(ownFingerprint, contactId)
        Log.i(TAG, "path3 fp=$fp: STUN=$ourStunStr room=${roomKey.take(16)}…")

        val peerHello: Signal.PeerHello? = try {
            coroutineScope {
                val sendClient = SignalingClient(workerUrl, ownFingerprint)
                // Collect ALL signals: respond to outbox_ping/relay_frame, terminate on peer_hello
                val collector = async {
                    withTimeoutOrNull(15_000L) {
                        var found: Signal.PeerHello? = null
                        sendClient.signals.collect { signal ->
                            when (signal) {
                                is Signal.PeerHello -> if (signal.fingerprint == contactId) {
                                    found = signal
                                    sendClient.disconnect()  // closes channel, ending collect
                                }
                                // Relay delivery is handled exclusively by the presence WS.
                                // Path3 must NOT respond to outbox_ping: if it sends outbox_ready
                                // and then disconnects before relay_frame arrives, the DO deletes
                                // the frame from storage and it is permanently lost.
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
        scope.launch { receiveLoop(contactId, conn) }
        conn.send(frame)
        Log.i(TAG, "path3 fp=$fp: sent ${frame.size} bytes via signaling/WAN path")
        return true
    }

    private suspend fun connectAndSend(
        contactId: String,
        host: String,
        port: Int,
        frame: ByteArray
    ): Boolean {
        val fp = contactId.take(8)
        return try {
            Log.d(TAG, "connectAndSend fp=$fp: connecting to $host:$port")
            val socket = connector.connectDirect(host, port)
            if (socket == null) {
                Log.w(TAG, "connectAndSend fp=$fp: timed out")
                return false
            }
            val conn = PeerConnection(socket)
            connections[contactId] = conn
            scope.launch { receiveLoop(contactId, conn) }
            conn.send(frame)
            Log.i(TAG, "connectAndSend fp=$fp: sent ${frame.size} bytes")
            true
        } catch (e: Exception) {
            Log.w(TAG, "connectAndSend fp=$fp: failed — ${e.message}")
            false
        }
    }

    private suspend fun enqueueOutbox(contactId: String, frame: ByteArray) {
        Log.i(TAG, "enqueueOutbox fp=${contactId.take(8)} frameBytes=${frame.size}")
        repository.insertPendingAction(
            PendingActionEntity(
                contactId = contactId,
                type = PendingActionEntity.TYPE_SEND_MESSAGE,
                payload = frame,
                createdAt = System.currentTimeMillis()
            )
        )
    }

    private fun startActiveBackoff(contactId: String) {
        val fp = contactId.take(8)
        backoffJobs[contactId]?.cancel()
        backoffJobs[contactId] = scope.launch {
            val delays = listOf(5_000L, 10_000L, 20_000L, 40_000L, 60_000L)
            var attempt = 0
            while (attempt < 20) {
                val delayMs = delays.getOrElse(attempt) { 60_000L }
                if (VERBOSE) Log.d(TAG, "backoff fp=$fp: attempt $attempt — waiting ${delayMs / 1000}s")
                delay(delayMs)
                if (VERBOSE) Log.d(TAG, "backoff fp=$fp: attempt $attempt — retrying")
                val flushed = flushOutboxForContact(contactId)
                if (flushed) {
                    Log.i(TAG, "backoff fp=$fp: outbox flushed on attempt $attempt")
                    break
                }
                attempt++
            }
            if (attempt >= 20) Log.w(TAG, "backoff fp=$fp: max attempts reached")
        }
    }

    private suspend fun flushOutboxForContact(contactId: String): Boolean {
        val fp = contactId.take(8)
        val actions = repository.getPendingActionsForContact(contactId)
        if (actions.isEmpty()) {
            if (VERBOSE) Log.d(TAG, "flush fp=$fp: outbox empty")
            return true
        }
        Log.i(TAG, "flush fp=$fp: flushing ${actions.size} pending action(s)")
        var allSent = true
        for (action in actions) {
            val sent = tryExistingConnection(contactId, action.payload)
                || tryLanConnect(contactId, action.payload)
                || tryStunConnect(contactId, action.payload)
                || tryRelayUpload(contactId, action.payload)

            if (sent) {
                repository.deletePendingAction(action.id)
                Log.i(TAG, "flush fp=$fp: action ${action.id} delivered and removed")
            } else {
                allSent = false
                repository.incrementRetryCount(action.id)
                Log.d(TAG, "flush fp=$fp: action ${action.id} still pending")
            }
        }
        return allSent
    }

    private suspend fun flushAllOutboxes() {
        val actions = repository.getAllPendingActions()
        if (actions.isEmpty()) {
            if (VERBOSE) Log.d(TAG, "flushAll: nothing pending")
            return
        }
        val byContact = actions.groupBy { it.contactId }
        Log.i(TAG, "flushAll: ${actions.size} action(s) across ${byContact.size} contact(s)")
        for ((contactId, _) in byContact) {
            backoffJobs[contactId]?.cancel()
            flushOutboxForContact(contactId)
        }
    }

    private suspend fun receiveLoop(contactId: String, conn: PeerConnection) {
        Log.d(TAG, "receiveLoop fp=${contactId.take(8)}: started")
        conn.receiveFlow().collect { frame ->
            Log.i(TAG, "receiveLoop fp=${contactId.take(8)}: received ${frame.size} bytes")
            processFrame(frame)
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
        Log.i(TAG, "handleIncoming: from $addr")
        val conn = PeerConnection(socket)
        scope.launch {
            conn.receiveFlow().collect { frame ->
                Log.i(TAG, "handleIncoming: received ${frame.size} bytes from $addr")
                processFrame(frame)
            }
            Log.d(TAG, "handleIncoming: flow ended for $addr")
        }
    }

    private suspend fun processFrame(frame: ByteArray) {
        // Wire frame layout: [4-byte inner length][32-byte senderFp][32-byte recipFp][16-byte uuid][8-byte ts][ciphertext]
        val minHeaderSize = 4 + 32 + 32 + 16 + 8
        if (frame.size < minHeaderSize) {
            Log.w(TAG, "processFrame: frame too short (${frame.size})")
            return
        }

        val senderFp = frame.copyOfRange(4, 36).joinToString("") { "%02x".format(it) }
        Log.i(TAG, "processFrame: frame=${frame.size}B sender=${senderFp.take(8)}")

        val contact = repository.getContact(senderFp) ?: run {
            Log.w(TAG, "processFrame: unknown sender ${senderFp.take(8)}")
            return
        }

        val sessionKey = try {
            ContactKey.deriveSessionKey(
                keyManager.getPrivateKeyBytes(),
                android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.w(TAG, "processFrame: key derivation failed — ${e.message}")
            return
        }

        val parsed = try {
            MessageCrypto.parseFrame(frame, sessionKey)
        } catch (e: Exception) {
            Log.w(TAG, "processFrame: decrypt/parse failed — ${e.message}")
            return
        }

        val payloadResult = try {
            MessageCrypto.parsePlaintext(parsed.plaintext)
        } catch (e: Exception) {
            Log.w(TAG, "processFrame: payload parse failed — ${e.message}")
            return
        }

        when (payloadResult.type) {
            MessageType.VOICE -> {
                Log.i(TAG, "processFrame: VOICE from ${senderFp.take(8)}")
                handleVoiceMessage(payloadResult.payload, parsed, contact, sessionKey)
            }
            MessageType.DELETE -> Log.d(TAG, "processFrame: DELETE (unhandled)")
            MessageType.PING   -> Log.d(TAG, "processFrame: PING")
            MessageType.ACK    -> Log.d(TAG, "processFrame: ACK")
        }
    }

    private suspend fun handleVoiceMessage(
        payload: ByteArray,
        frame: ParsedFrame,
        contact: ContactEntity,
        sessionKey: ByteArray
    ) {
        if (payload.size < 4 + 8) {
            Log.w(TAG, "handleVoiceMessage: payload too short")
            return
        }
        val buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val durationMs = buf.int
        val deleteAfterMs = buf.long
        val opusSize = payload.size - 4 - 8
        if (opusSize <= 0) {
            Log.w(TAG, "handleVoiceMessage: empty audio")
            return
        }
        val opusBytes = ByteArray(opusSize).also { buf.get(it) }

        val uuid = frame.uuid.toString()

        if (repository.getMessage(uuid) != null) {
            Log.d(TAG, "handleVoiceMessage: duplicate, ignoring $uuid")
            return
        }

        val messagesDir = File(context.filesDir, "messages")
        messagesDir.mkdirs()
        val encFile = File(messagesDir, "$uuid.enc")
        encFile.writeBytes(MessageCrypto.encrypt(sessionKey, opusBytes))

        val now = System.currentTimeMillis()
        repository.insertMessage(
            MessageEntity(
                uuid = uuid,
                contactId = contact.id,
                direction = MessageEntity.DIRECTION_INBOUND,
                state = MessageEntity.STATE_DELIVERED,
                encryptedFilePath = encFile.absolutePath,
                durationMs = durationMs,
                deleteAfterMs = deleteAfterMs,
                scheduledDeleteAt = if (deleteAfterMs > 0) now + deleteAfterMs else 0L,
                transcription = null,
                createdAt = frame.timestampMs,
                sentAt = 0L,
                deliveredAt = now
            )
        )

        notificationHelper.notifyIncoming(contact, uuid, durationMs)
        Log.i(TAG, "handleVoiceMessage: saved ${durationMs}ms from ${contact.id.take(8)}")
    }

    private suspend fun startLanDiscovery() {
        Log.i(TAG, "startLanDiscovery: registering _voicedrop._tcp on port $listenPort")
        lanDiscovery = LanDiscovery(context, ownFingerprint)
        lanDiscovery?.start(listenPort)
        lanDiscovery?.discoveredPeers?.collect { peer ->
            Log.i(TAG, "LAN: fp=${peer.fingerprint.take(8)} at ${peer.host}:${peer.port}")
            lanPeers[peer.fingerprint] = peer

            if (lanDiscovery!!.shouldInitiate(peer.fingerprint)) {
                Log.d(TAG, "LAN: we initiate to fp=${peer.fingerprint.take(8)}")
                val actions = repository.getPendingActionsForContact(peer.fingerprint)
                Log.d(TAG, "LAN: ${actions.size} pending action(s) for fp=${peer.fingerprint.take(8)}")
                for (action in actions) {
                    val sent = connectAndSend(peer.fingerprint, peer.host, peer.port, action.payload)
                    if (sent) repository.deletePendingAction(action.id)
                }
            } else {
                Log.d(TAG, "LAN: peer fp=${peer.fingerprint.take(8)} initiates — we listen")
            }
        }
    }

    private suspend fun startSignalingPresence() {
        Log.i(TAG, "presence: starting (workerUrl=${workerUrl.take(40)})")

        // Watch the contacts Flow so new contacts get a presence connection immediately after pairing
        val presenceJobs = mutableMapOf<String, Job>()
        try {
            repository.getAllContacts().collect { contacts ->
                val currentIds = contacts.map { it.id }.toSet()

                // Cancel connections for contacts that were removed
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

                // Start presence loops for newly added contacts
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
                                            Log.i(TAG, "presence: fp=${contact.id.take(8)} appeared at ${signal.stunAddr}")
                                            backoffMs = 3_000L
                                            val pending = repository.getPendingActionsForContact(contact.id)
                                            if (pending.isNotEmpty()) {
                                                Log.d(TAG, "presence: flushing ${pending.size} pending action(s) for fp=${contact.id.take(8)}")
                                                flushOutboxForContact(contact.id)
                                            }
                                        }
                                        is Signal.Presence -> Log.d(TAG, "presence: peer fp=${contact.id.take(8)} online=${signal.online}")
                                        is Signal.OutboxPing -> {
                                            Log.i(TAG, "presence: outbox_ping fp=${contact.id.take(8)} count=${signal.count}")
                                            pullAndDeliverRelay(contact.id, roomKey)
                                        }
                                        is Signal.RelayFrame -> {
                                            try {
                                                val bytes = android.util.Base64.decode(signal.data, android.util.Base64.NO_WRAP)
                                                Log.i(TAG, "presence: relay_frame fp=${contact.id.take(8)} size=${bytes.size}")
                                                processFrame(bytes)
                                            } catch (e: Exception) {
                                                Log.w(TAG, "presence: relay_frame error fp=${contact.id.take(8)} — ${e.message}")
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
                    processFrame(bytes)
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
        // Set false once end-to-end delivery is confirmed working to reduce logcat noise
        private const val VERBOSE = true
    }
}
