package com.voicedrop.network

import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.IdentityKeys
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Tink-backed [IdentityKeys] for tests: a real X25519 keypair so the DH proof
 * verifies, with no AndroidKeyStore (which KeyManager's init needs but Robolectric lacks).
 * Honors the frozen byte contract: getPublicKeyBase64() == NO_WRAP(getPublicKeyBytes()).
 */
private class FakeIdentityKeys : IdentityKeys {
    private val priv = X25519.generatePrivateKey()
    private val pub = X25519.publicFromPrivate(priv)
    override fun getPublicKeyBytes(): ByteArray = pub.copyOf()
    override fun getPrivateKeyBytes(): ByteArray = priv.copyOf()
    override fun getPublicKeyBase64(): String =
        android.util.Base64.encodeToString(pub, android.util.Base64.NO_WRAP)
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class SignalingClientTest {

    private lateinit var server: MockWebServer
    private val serverReceived = LinkedBlockingQueue<String>()
    private val serverSocket = AtomicReference<WebSocket?>(null)
    private lateinit var client: SignalingClient
    private lateinit var identityKeys: FakeIdentityKeys
    private lateinit var ownFingerprint: String
    private val stunAddr = "192.0.2.10:9000"
    // encodeDefaults so server→client `encodeToString` emits the defaulted `type` field
    // (production worker sends it; client's parseSignal dispatches on it). Mirrors
    // SignalingClient's own json. Other tests only decode with this json, so this is safe.
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Before
    fun setUp() {
        identityKeys = FakeIdentityKeys()
        ownFingerprint = PullAuth.fingerprintBytes(identityKeys.getPublicKeyBytes())
            .joinToString("") { "%02x".format(it) }
        server = MockWebServer()
        val listener = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                serverSocket.set(ws)
            }

            override fun onMessage(ws: WebSocket, text: String) {
                serverReceived.add(text)
            }

            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                // Complete the close handshake so MockWebServer's per-connection task
                // queue can become idle. Without this, shutdown() waits 5s for the
                // half-closed WebSocket queue and then throws IOException.
                ws.close(code, null)
            }
        }
        server.enqueue(MockResponse().withWebSocketUpgrade(listener))
        server.start()

        val url = "ws://${server.hostName}:${server.port}"
        client = SignalingClient(url, ownFingerprint, identityKeys)
        assertTrue(client.connect("room-1", stunAddr))
    }

    @After
    fun tearDown() {
        client.disconnect()
        // Force-close server side in case the test didn't trigger a clean close handshake.
        serverSocket.getAndSet(null)?.close(1000, "tearDown")
        server.shutdown()
    }

    private fun nextServerMessage(): String {
        val msg = serverReceived.poll(5, TimeUnit.SECONDS)
        assertNotNull("Expected message from client within 5s", msg)
        return msg!!
    }

    /** Drain the two messages the client auto-sends on open: hello, then auth_request. */
    private fun drainHandshakeFromClient() {
        nextServerMessage() // hello
        nextServerMessage() // auth_request
    }

    @Test
    fun connect_sendsHelloOnOpen() {
        val obj = json.parseToJsonElement(nextServerMessage()).jsonObject
        assertEquals("hello", obj["type"]?.jsonPrimitive?.content)
        assertEquals(ownFingerprint, obj["fingerprint"]?.jsonPrimitive?.content)
        assertEquals(stunAddr, obj["stunAddr"]?.jsonPrimitive?.content)
    }

    @Test
    fun send_serializesAllSignalSubclassesWithTypeField() {
        // Drain hello + auth_request first; also confirms the WebSocket is open before further sends.
        drainHandshakeFromClient()

        val outbound = listOf(
            Signal.Hello(fingerprint = "FP-A", stunAddr = "1.1.1.1:1"),
            Signal.PeerHello(fingerprint = "FP-B", stunAddr = "2.2.2.2:2"),
            Signal.Presence(online = true),
            Signal.OutboxPing(count = 7),
            Signal.OutboxReady(),
            Signal.RelayFrame(data = "abc-base64==")
        )
        outbound.forEach { client.send(it) }

        val received = outbound.map { json.parseToJsonElement(nextServerMessage()).jsonObject }

        assertEquals("hello", received[0]["type"]?.jsonPrimitive?.content)
        assertEquals("FP-A", received[0]["fingerprint"]?.jsonPrimitive?.content)
        assertEquals("1.1.1.1:1", received[0]["stunAddr"]?.jsonPrimitive?.content)

        assertEquals("peer_hello", received[1]["type"]?.jsonPrimitive?.content)
        assertEquals("FP-B", received[1]["fingerprint"]?.jsonPrimitive?.content)
        assertEquals("2.2.2.2:2", received[1]["stunAddr"]?.jsonPrimitive?.content)

        assertEquals("presence", received[2]["type"]?.jsonPrimitive?.content)
        assertEquals(true, received[2]["online"]?.jsonPrimitive?.boolean)

        assertEquals("outbox_ping", received[3]["type"]?.jsonPrimitive?.content)
        assertEquals(7, received[3]["count"]?.jsonPrimitive?.int)

        assertEquals("outbox_ready", received[4]["type"]?.jsonPrimitive?.content)

        assertEquals("relay_frame", received[5]["type"]?.jsonPrimitive?.content)
        assertEquals("abc-base64==", received[5]["data"]?.jsonPrimitive?.content)
    }

    @Test
    fun signals_deserializesAllInboundSubclasses() = runBlocking {
        // After auto-hello arrives at the server, serverSocket has been set in onOpen.
        nextServerMessage()
        val ws = serverSocket.get()!!

        ws.send("""{"type":"peer_hello","fingerprint":"FP-C","stunAddr":"3.3.3.3:3"}""")
        ws.send("""{"type":"presence","online":false}""")
        ws.send("""{"type":"outbox_ping","count":11}""")
        ws.send("""{"type":"outbox_ready"}""")
        ws.send("""{"type":"relay_frame","data":"xyz=="}""")

        val signals = withTimeout(5_000L) {
            client.signals.take(5).toList()
        }

        assertEquals(Signal.PeerHello(fingerprint = "FP-C", stunAddr = "3.3.3.3:3"), signals[0])
        assertEquals(Signal.Presence(online = false), signals[1])
        assertEquals(Signal.OutboxPing(count = 11), signals[2])
        assertEquals(Signal.OutboxReady(), signals[3])
        assertEquals(Signal.RelayFrame(data = "xyz=="), signals[4])
    }

    @Test
    fun roundTrip_clientSerializedSignalsParseBackToOriginals() = runBlocking {
        // Drain hello + auth_request so subsequent server-received items are exactly what client.send produced.
        drainHandshakeFromClient()
        val ws = serverSocket.get()!!

        // Excludes Signal.Hello: parseSignal() drops "hello" (client-only outbound type).
        val originals = listOf<Signal>(
            Signal.PeerHello(fingerprint = "FP-D", stunAddr = "4.4.4.4:4"),
            Signal.Presence(online = true),
            Signal.OutboxPing(count = 99),
            Signal.OutboxReady(),
            Signal.RelayFrame(data = "round-trip-data==")
        )
        originals.forEach { client.send(it) }

        val wireBytes = originals.map { nextServerMessage() }
        wireBytes.forEach { ws.send(it) }

        val received = withTimeout(5_000L) {
            client.signals.take(originals.size).toList()
        }
        assertEquals(originals, received)
    }

    @Test
    fun handshake_yields_token() = runBlocking {
        // 1. Drain hello; capture the auth_request to read the client's identityPub.
        nextServerMessage() // hello
        val authReq = json.parseToJsonElement(nextServerMessage()).jsonObject
        assertEquals("auth_request", authReq["type"]?.jsonPrimitive?.content)
        val clientPub = android.util.Base64.decode(
            authReq["identityPub"]!!.jsonPrimitive.content, android.util.Base64.NO_WRAP
        )

        // 2. Server generates its own X25519 keypair + nonce; sends auth_challenge.
        val serverPriv = X25519.generatePrivateKey()
        val serverPub = X25519.publicFromPrivate(serverPriv)
        val nonce = ByteArray(16) { it.toByte() }
        val ws = serverSocket.get()!!
        ws.send(
            json.encodeToString(
                Signal.AuthChallenge(
                    serverPub = android.util.Base64.encodeToString(serverPub, android.util.Base64.NO_WRAP),
                    nonce = android.util.Base64.encodeToString(nonce, android.util.Base64.NO_WRAP)
                )
            )
        )

        // 3. Client replies auth_response{mac}; server VERIFIES the proof (DH symmetry).
        val authResp = json.parseToJsonElement(nextServerMessage()).jsonObject
        assertEquals("auth_response", authResp["type"]?.jsonPrimitive?.content)
        val gotMac = android.util.Base64.decode(
            authResp["mac"]!!.jsonPrimitive.content, android.util.Base64.NO_WRAP
        )
        val fp = PullAuth.fingerprintBytes(clientPub)
        val expectedMac = PullAuth.macWithKey(X25519.computeSharedSecret(serverPriv, clientPub), nonce, fp)
        assertArrayEquals("client proof MAC must verify server-side", expectedMac, gotMac)

        // 4. Server issues a token; client must store it.
        ws.send(
            json.encodeToString(
                Signal.AuthToken(token = "test-token", expiresAt = 9_999_999_999_999L)
            )
        )

        // 5. Poll until the client stores it (onMessage runs on the WS callback thread).
        withTimeout(5_000L) {
            while (client.authToken == null) kotlinx.coroutines.delay(20)
        }
        assertEquals("test-token", client.authToken)
    }
}
