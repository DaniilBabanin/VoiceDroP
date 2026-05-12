package com.voicedrop.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

class PeerConnector {

    suspend fun holePunch(localPort: Int, remoteAddr: InetSocketAddress): Socket? =
        withContext(Dispatchers.IO) {
            Log.d(TAG, "holePunch: localPort=$localPort remote=$remoteAddr")
            val result = withTimeoutOrNull(10_000L) {
                try {
                    val socket = Socket()
                    socket.reuseAddress = true
                    trySetReusePort(socket)
                    socket.bind(InetSocketAddress(localPort))
                    socket.connect(remoteAddr, 10_000)
                    socket
                } catch (e: Exception) {
                    Log.w(TAG, "holePunch: failed — ${e.javaClass.simpleName}: ${e.message}")
                    null
                }
            }
            if (result != null) Log.i(TAG, "holePunch: success to $remoteAddr")
            else Log.w(TAG, "holePunch: timed out or failed for $remoteAddr")
            result
        }

    suspend fun connectDirect(host: String, port: Int): Socket? =
        withContext(Dispatchers.IO) {
            Log.d(TAG, "connectDirect: $host:$port (5s timeout)")
            try {
                // Socket(host, port) has no timeout — use connect(addr, ms) so the OS
                // honours the deadline instead of retrying SYN for ~2 minutes.
                val socket = Socket()
                socket.connect(InetSocketAddress(host, port), 5_000)
                Log.i(TAG, "connectDirect: connected to $host:$port")
                socket
            } catch (e: Exception) {
                Log.w(TAG, "connectDirect: failed — ${e.javaClass.simpleName}: ${e.message}")
                null
            }
        }

    suspend fun listenForIncoming(localPort: Int): Socket? =
        withContext(Dispatchers.IO) {
            Log.d(TAG, "listenForIncoming: port=$localPort (10s timeout)")
            val result = withTimeoutOrNull(10_000L) {
                try {
                    val serverSocket = java.net.ServerSocket(localPort)
                    serverSocket.soTimeout = 10_000
                    val client = serverSocket.accept()
                    serverSocket.close()
                    client
                } catch (e: Exception) {
                    Log.w(TAG, "listenForIncoming: failed — ${e.javaClass.simpleName}: ${e.message}")
                    null
                }
            }
            if (result != null) Log.i(TAG, "listenForIncoming: got connection on port $localPort")
            else Log.w(TAG, "listenForIncoming: timed out on port $localPort")
            result
        }

    companion object {
        private const val TAG = "VoiceDrop/Connector"
    }

    private fun trySetReusePort(socket: Socket) {
        try {
            val method = Socket::class.java.getMethod(
                "setOption",
                java.net.SocketOption::class.java,
                Any::class.java
            )
            val option = Class.forName("jdk.net.ExtendedSocketOptions")
                .getField("SO_REUSEPORT")
                .get(null) as java.net.SocketOption<*>
            @Suppress("UNCHECKED_CAST")
            method.invoke(socket, option, true)
        } catch (_: Exception) {
            // SO_REUSEPORT not available; hole-punch may fail on some NATs
        }
    }
}
