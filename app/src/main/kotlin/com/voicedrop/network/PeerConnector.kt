package com.voicedrop.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

class PeerConnector {

    suspend fun holePunch(localPort: Int, remoteAddr: InetSocketAddress): Socket? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(10_000L) {
                try {
                    val socket = Socket()
                    socket.reuseAddress = true
                    trySetReusePort(socket)
                    socket.bind(InetSocketAddress(localPort))
                    socket.connect(remoteAddr, 10_000)
                    socket
                } catch (e: Exception) {
                    null
                }
            }
        }

    suspend fun connectDirect(host: String, port: Int): Socket? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(5_000L) {
                try {
                    Socket(host, port)
                } catch (e: Exception) {
                    null
                }
            }
        }

    suspend fun listenForIncoming(localPort: Int): Socket? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(10_000L) {
                try {
                    val serverSocket = java.net.ServerSocket(localPort)
                    serverSocket.soTimeout = 10_000
                    val client = serverSocket.accept()
                    serverSocket.close()
                    client
                } catch (e: Exception) {
                    null
                }
            }
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
