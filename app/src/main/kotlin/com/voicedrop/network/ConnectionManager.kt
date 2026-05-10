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
            scope.launch { flushAllOutboxes() }
        }
    }

    fun start() {
        connectivityManager.registerNetworkCallback(
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build(),
            networkCallback
        )

        listenPort = (10000..60000).random()
        scope.launch { startListening() }
        scope.launch { startLanDiscovery() }
    }

    fun stop() {
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        lanDiscovery?.stop()
        signalingClient?.disconnect()
        listenServerSocket?.close()
        connections.values.forEach { it.close() }
        scope.cancel()
    }

    fun onAppForeground() {
        scope.launch { flushAllOutboxes() }
    }

    suspend fun sendToContact(contactId: String, frame: ByteArray) {
        val mutex = mutexes.getOrPut(contactId) { Mutex() }
        mutex.withLock {
            val sent = tryExistingConnection(contactId, frame)
                || tryLanConnect(contactId, frame)
                || tryStunConnect(contactId, frame)

            if (!sent) {
                enqueueOutbox(contactId, frame)
                startActiveBackoff(contactId)
            }
        }
    }

    private suspend fun tryExistingConnection(contactId: String, frame: ByteArray): Boolean {
        val conn = connections[contactId] ?: return false
        return if (conn.isAlive) {
            try {
                conn.send(frame)
                true
            } catch (e: Exception) {
                connections.remove(contactId)
                false
            }
        } else {
            connections.remove(contactId)
            false
        }
    }

    private suspend fun tryLanConnect(contactId: String, frame: ByteArray): Boolean {
        val contact = repository.getContact(contactId) ?: return false
        val peer = withTimeoutOrNull(5_000L) {
            // Check if LAN peer is already known via mDNS
            null as LanPeer?
        } ?: return false

        return connectAndSend(contactId, peer.host, peer.port, frame)
    }

    private suspend fun tryStunConnect(contactId: String, frame: ByteArray): Boolean {
        if (workerUrl.isBlank()) return false
        val stunAddr = stunClient.getPublicAddress() ?: return false
        // In practice: exchange via signaling, hole-punch, send
        // Simplified: try direct connect via signaling-coordinated address
        return false
    }

    private suspend fun connectAndSend(
        contactId: String,
        host: String,
        port: Int,
        frame: ByteArray
    ): Boolean {
        return try {
            val socket = connector.connectDirect(host, port) ?: return false
            val conn = PeerConnection(socket)
            connections[contactId] = conn
            scope.launch { receiveLoop(contactId, conn) }
            conn.send(frame)
            true
        } catch (e: Exception) {
            false
        }
    }

    private suspend fun enqueueOutbox(contactId: String, frame: ByteArray) {
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
        backoffJobs[contactId]?.cancel()
        backoffJobs[contactId] = scope.launch {
            val delays = listOf(5_000L, 10_000L, 20_000L, 40_000L, 60_000L)
            var attempt = 0
            while (attempt < 20) {
                delay(delays.getOrElse(attempt) { 60_000L })
                val flushed = flushOutboxForContact(contactId)
                if (flushed) break
                attempt++
            }
        }
    }

    private suspend fun flushOutboxForContact(contactId: String): Boolean {
        val actions = repository.getPendingActionsForContact(contactId)
        if (actions.isEmpty()) return true

        var allSent = true
        for (action in actions) {
            val sent = tryExistingConnection(contactId, action.payload)
                || tryLanConnect(contactId, action.payload)
                || tryStunConnect(contactId, action.payload)

            if (sent) {
                repository.deletePendingAction(action.id)
            } else {
                allSent = false
                repository.incrementRetryCount(action.id)
            }
        }
        return allSent
    }

    private suspend fun flushAllOutboxes() {
        val actions = repository.getAllPendingActions()
        val byContact = actions.groupBy { it.contactId }
        for ((contactId, _) in byContact) {
            backoffJobs[contactId]?.cancel()
            flushOutboxForContact(contactId)
        }
    }

    private suspend fun receiveLoop(contactId: String, conn: PeerConnection) {
        conn.receiveFlow().collect { frame ->
            // Incoming frames are handled by VoiceDropService
            Log.d(TAG, "Received frame from $contactId (${frame.size} bytes)")
        }
    }

    private suspend fun startListening() {
        val server = ServerSocket(listenPort)
        listenServerSocket = server
        while (true) {
            try {
                val socket = server.accept()
                scope.launch { handleIncoming(socket) }
            } catch (e: Exception) {
                break
            }
        }
    }

    private suspend fun handleIncoming(socket: Socket) {
        val conn = PeerConnection(socket)
        // Identify the peer from the first frame and register connection
        Log.d(TAG, "Incoming connection from ${socket.inetAddress.hostAddress}")
    }

    private suspend fun startLanDiscovery() {
        // LanDiscovery initialized with contacts from repository
        val contacts = mutableSetOf<String>()
        lanDiscovery = LanDiscovery(context, ownFingerprint, contacts)
        lanDiscovery?.start(listenPort)
        lanDiscovery?.discoveredPeers?.collect { peer ->
            if (lanDiscovery!!.shouldInitiate(peer.fingerprint)) {
                val contactId = peer.fingerprint
                val actions = repository.getPendingActionsForContact(contactId)
                for (action in actions) {
                    val sent = connectAndSend(contactId, peer.host, peer.port, action.payload)
                    if (sent) repository.deletePendingAction(action.id)
                }
            }
        }
    }

    companion object {
        private const val TAG = "ConnectionManager"
    }
}
