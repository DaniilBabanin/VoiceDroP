package com.voicedrop.network

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.Socket

class FramingTest {

    @Test
    fun sendReceiveRoundTrip() = runBlocking {
        val serverIn = PipedInputStream()
        val clientOut = PipedOutputStream(serverIn)
        val clientIn = PipedInputStream()
        val serverOut = PipedOutputStream(clientIn)

        val clientSocket = object : Socket() {
            override fun getInputStream() = clientIn
            override fun getOutputStream() = clientOut
            override fun isConnected() = true
            override fun isClosed() = false
        }

        val serverSocket = object : Socket() {
            override fun getInputStream() = serverIn
            override fun getOutputStream() = serverOut
            override fun isConnected() = true
            override fun isClosed() = false
        }

        val client = PeerConnection(clientSocket)
        val server = PeerConnection(serverSocket)

        val testData = "Hello from client".toByteArray()
        client.send(testData)
        clientOut.close() // EOF unblocks the next read in receiveFlow so first() can terminate

        val received = server.receiveFlow().first()
        assertArrayEquals(testData, received)
    }

    @Test
    fun largeFrameRoundTrip() = runBlocking {
        val serverIn = PipedInputStream(65536)
        val clientOut = PipedOutputStream(serverIn)
        val clientIn = PipedInputStream(65536)
        val serverOut = PipedOutputStream(clientIn)

        val clientSocket = object : Socket() {
            override fun getInputStream() = clientIn
            override fun getOutputStream() = clientOut
            override fun isConnected() = true
            override fun isClosed() = false
        }

        val serverSocket = object : Socket() {
            override fun getInputStream() = serverIn
            override fun getOutputStream() = serverOut
            override fun isConnected() = true
            override fun isClosed() = false
        }

        val client = PeerConnection(clientSocket)
        val server = PeerConnection(serverSocket)

        val testData = ByteArray(32768) { (it % 256).toByte() }
        client.send(testData)
        clientOut.close() // EOF unblocks the next read in receiveFlow so first() can terminate

        val received = server.receiveFlow().first()
        assertArrayEquals(testData, received)
    }
}
