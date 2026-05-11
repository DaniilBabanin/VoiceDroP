package com.voicedrop.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.voicedrop.storage.MessageRepository
import com.voicedrop.storage.PendingActionEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.net.ServerSocket
import java.net.Socket

class ConnectionManager(
    private val context: Context,
    private val repository: MessageRepository,
    private val ownFingerprint: String,
    private val workerUrl: String
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val connections = mutableMapOf<String, PeerConnection>()
    private val mutexes = mutableMapOf<String, Mutex>()
    private val backoffJobs = mutableMapOf<String, Job>()
    private val connector = PeerConnector()
    private val stunClient = StunClient()

    private var signalingClient: SignalingClient? = null
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
    }

    fun stop() {
        Log.i(TAG, "stop")
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        lanDiscovery?.stop()
        signalingClient?.disconnect()
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

            if (sent) {
                Log.i(TAG, "sendToContact fp=$fp: delivered")
            } else {
                Log.w(TAG, "sendToContact fp=$fp: all paths failed — queuing outbox")
                enqueueOutbox(contactId, frame)
                startActiveBackoff(contactId)
            }
        }
    }

    private suspend fun tryExistingConnection(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        val conn = connections[contactId]
        if (conn == null) {
            Log.d(TAG, "path1 fp=$fp: no existing connection")
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
            Log.d(TAG, "path1 fp=$fp: existing connection not alive")
            connections.remove(contactId)
            false
        }
    }

    private suspend fun tryLanConnect(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        Log.d(TAG, "path2 fp=$fp: trying LAN (5s timeout)")
        val peer = withTimeoutOrNull(5_000L) {
            null as LanPeer?
        }
        if (peer == null) {
            Log.d(TAG, "path2 fp=$fp: no LAN peer found")
            return false
        }
        Log.i(TAG, "path2 fp=$fp: LAN peer found at ${peer.host}:${peer.port}")
        return connectAndSend(contactId, peer.host, peer.port, frame)
    }

    private suspend fun tryStunConnect(contactId: String, frame: ByteArray): Boolean {
        val fp = contactId.take(8)
        if (workerUrl.isBlank()) {
            Log.d(TAG, "path3 fp=$fp: skipped (no signaling URL configured)")
            return false
        }
        Log.d(TAG, "path3 fp=$fp: getting STUN address")
        val stunAddr = stunClient.getPublicAddress()
        if (stunAddr == null) {
            Log.w(TAG, "path3 fp=$fp: STUN failed — no public address")
            return false
        }
        Log.i(TAG, "path3 fp=$fp: STUN resolved $stunAddr — signaling/hole-punch not yet implemented")
        return false
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
                Log.w(TAG, "connectAndSend fp=$fp: connectDirect timed out")
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
                Log.d(TAG, "backoff fp=$fp: attempt $attempt — waiting ${delayMs / 1000}s")
                delay(delayMs)
                Log.d(TAG, "backoff fp=$fp: attempt $attempt — retrying")
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
            Log.d(TAG, "flush fp=$fp: outbox empty")
            return true
        }
        Log.i(TAG, "flush fp=$fp: flushing ${actions.size} pending action(s)")
        var allSent = true
        for (action in actions) {
            val sent = tryExistingConnection(contactId, action.payload)
                || tryLanConnect(contactId, action.payload)
                || tryStunConnect(contactId, action.payload)

            if (sent) {
                repository.deletePendingAction(action.id)
                Log.i(TAG, "flush fp=$fp: action ${action.id} delivered and removed")
            } else {
                allSent = false
                repository.incrementRetryCount(action.id)
                Log.d(TAG, "flush fp=$fp: action ${action.id} still pending (retry count incremented)")
            }
        }
        return allSent
    }

    private suspend fun flushAllOutboxes() {
        val actions = repository.getAllPendingActions()
        if (actions.isEmpty()) {
            Log.d(TAG, "flushAll: nothing pending")
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
        Log.i(TAG, "startListening: accepting connections on port $listenPort")
        while (true) {
            try {
                val socket = server.accept()
                Log.i(TAG, "startListening: incoming connection from ${socket.inetAddress.hostAddress}")
                scope.launch { handleIncoming(socket) }
            } catch (e: Exception) {
                Log.d(TAG, "startListening: server socket closed — ${e.message}")
                break
            }
        }
    }

    private suspend fun handleIncoming(socket: Socket) {
        val addr = socket.inetAddress.hostAddress
        Log.i(TAG, "handleIncoming: from $addr — awaiting first frame to identify peer")
        val conn = PeerConnection(socket)
        // TODO: read first frame, extract sender fingerprint, register connection
    }

    private suspend fun startLanDiscovery() {
        Log.i(TAG, "startLanDiscovery: registering _voicedrop._tcp on port $listenPort")
        val contacts = mutableSetOf<String>()
        lanDiscovery = LanDiscovery(context, ownFingerprint, contacts)
        lanDiscovery?.start(listenPort)
        lanDiscovery?.discoveredPeers?.collect { peer ->
            Log.i(TAG, "LAN peer discovered: fp=${peer.fingerprint.take(8)} at ${peer.host}:${peer.port}")
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

    companion object {
        private const val TAG = "VoiceDrop/Net"
    }
}
