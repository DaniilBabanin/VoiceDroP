package com.voicedrop.network

import android.util.Log
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

sealed class Signal {
    @Serializable
    data class Hello(val type: String = "hello", val fingerprint: String, val stunAddr: String) : Signal()

    @Serializable
    data class PeerHello(val type: String = "peer_hello", val fingerprint: String, val stunAddr: String) : Signal()

    @Serializable
    data class Presence(val type: String = "presence", val online: Boolean) : Signal()

    @Serializable
    data class OutboxPing(val type: String = "outbox_ping", val count: Int) : Signal()

    @Serializable
    data class OutboxReady(val type: String = "outbox_ready") : Signal()

    @Serializable
    data class RelayFrame(val type: String = "relay_frame", val data: String) : Signal()
}

class SignalingClient(
    private val workerUrl: String,
    private val ownFingerprint: String
) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        // Send periodic pings so OkHttp detects a zombie connection (server-side DO terminated
        // without a clean WS close frame) and fires onFailure → collect() ends → reconnect.
        // Detection = up to 2 × interval after server dies.
        .pingInterval(20, TimeUnit.SECONDS)
        .build()

    private val signalChannel = Channel<Signal>(Channel.UNLIMITED)
    private var webSocket: WebSocket? = null
    private val json = Json { ignoreUnknownKeys = true }

    val signals: Flow<Signal> = signalChannel.receiveAsFlow()

    val isConfigured: Boolean get() = workerUrl.isNotBlank()

    fun connect(roomKey: String, stunAddr: String): Boolean {
        if (workerUrl.isBlank()) return false

        // workerUrl is the full signal endpoint, e.g. wss://host/signal
        val url = "${workerUrl.trimEnd('/')}/$roomKey"
        Log.d(TAG, "connect: $url (stunAddr=$stunAddr)")

        val request = Request.Builder().url(url).build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i(TAG, "onOpen: room=$roomKey — sending hello")
                val hello = """{"type":"hello","fingerprint":"$ownFingerprint","stunAddr":"$stunAddr"}"""
                ws.send(hello)
            }

            override fun onMessage(ws: WebSocket, text: String) {
                Log.d(TAG, "onMessage: $text")
                parseSignal(text)?.let { signalChannel.trySend(it) }
            }

            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "onClosing: code=$code reason=$reason")
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "onClosed: code=$code")
                signalChannel.close()
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "onFailure: ${t.javaClass.simpleName}: ${t.message}")
                signalChannel.close()
            }
        })
        return true
    }

    fun send(signal: Signal) {
        val text = when (signal) {
            is Signal.Hello -> json.encodeToString<Signal.Hello>(signal)
            is Signal.PeerHello -> json.encodeToString<Signal.PeerHello>(signal)
            is Signal.Presence -> json.encodeToString<Signal.Presence>(signal)
            is Signal.OutboxPing -> json.encodeToString<Signal.OutboxPing>(signal)
            is Signal.OutboxReady -> json.encodeToString<Signal.OutboxReady>(signal)
            is Signal.RelayFrame -> json.encodeToString<Signal.RelayFrame>(signal)
        }
        val sent = webSocket?.send(text)
        Log.d(TAG, "send: ${signal.javaClass.simpleName} sent=$sent")
    }

    fun disconnect() {
        Log.d(TAG, "disconnect")
        webSocket?.close(1000, "Done")
        webSocket = null
        signalChannel.close()  // terminate collect immediately; onClosed may arrive late
    }

    private fun parseSignal(text: String): Signal? {
        return try {
            val obj = json.parseToJsonElement(text) as? JsonObject ?: return null
            when (obj["type"]?.jsonPrimitive?.content) {
                "peer_hello" -> json.decodeFromString<Signal.PeerHello>(text)
                "presence"   -> json.decodeFromString<Signal.Presence>(text)
                "outbox_ping" -> json.decodeFromString<Signal.OutboxPing>(text)
                "outbox_ready" -> json.decodeFromString<Signal.OutboxReady>(text)
                "relay_frame"  -> json.decodeFromString<Signal.RelayFrame>(text)
                else -> null
            }
        } catch (e: Exception) {
            Log.w(TAG, "parseSignal failed: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "VoiceDrop/Signaling"
    }
}
