package com.voicedrop.network

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow

data class LanPeer(val fingerprint: String, val host: String, val port: Int)

/**
 * NSD/mDNS LAN discovery. The advertised service name is NOT the raw identity
 * fingerprint (cleartext multicast would let any passive LAN host enumerate
 * present VoiceDrop identities) but a daily-rotating pseudonym derived from it:
 * `vd-` + SHA-256("voicedrop/lan/v1" || epochDay || fp)[0..8]. Only peers who
 * already know a contact's fingerprint can recompute and match it. Yesterday's
 * epoch is also matched to tolerate clock skew and long-lived registrations.
 *
 * The resolved address is a HINT only — any LAN host can still advertise a
 * matching name. Content stays sealed by the ratchet AEAD; a spoofed entry can
 * only black-hole the LAN path (delivery falls back to P2P/relay).
 */
class LanDiscovery(
    private val context: Context,
    private val ownFingerprint: String,
    /** Lowercase-hex fingerprints of paired contacts (for pseudonym matching). */
    private val knownFingerprints: () -> Collection<String> = { emptyList() }
) {

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    private val peerChannel = Channel<LanPeer>(Channel.UNLIMITED)
    val discoveredPeers: Flow<LanPeer> = peerChannel.receiveAsFlow()

    private var multicastLock: WifiManager.MulticastLock? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    private var listenPort: Int = 0

    fun start(listenPort: Int) {
        this.listenPort = listenPort

        multicastLock = wifiManager.createMulticastLock("voicedrop").apply {
            setReferenceCounted(true)
            acquire()
        }

        registerService(listenPort)
        startDiscovery()
    }

    fun stop() {
        registrationListener?.let { runCatching { nsdManager.unregisterService(it) } }
        discoveryListener?.let { runCatching { nsdManager.stopServiceDiscovery(it) } }
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
    }

    fun shouldInitiate(peerFingerprint: String): Boolean =
        ownFingerprint < peerFingerprint

    private fun registerService(port: Int) {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = pseudonym(ownFingerprint, currentEpochDay())
            serviceType = SERVICE_TYPE
            this.port = port
        }

        registrationListener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(info: NsdServiceInfo) {
                Log.i(TAG, "NSD registered: ${info.serviceName} on port $port")
            }
            override fun onRegistrationFailed(info: NsdServiceInfo, errorCode: Int) {
                Log.e(TAG, "NSD registration failed: errorCode=$errorCode")
            }
            override fun onServiceUnregistered(info: NsdServiceInfo) {
                Log.d(TAG, "NSD unregistered: ${info.serviceName}")
            }
            override fun onUnregistrationFailed(info: NsdServiceInfo, errorCode: Int) {
                Log.w(TAG, "NSD unregistration failed: errorCode=$errorCode")
            }
        }

        nsdManager.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, registrationListener)
    }

    private fun startDiscovery() {
        discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "NSD discovery start failed: errorCode=$errorCode")
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.w(TAG, "NSD discovery stop failed: errorCode=$errorCode")
            }
            override fun onDiscoveryStarted(serviceType: String) {
                Log.i(TAG, "NSD discovery started for $serviceType")
            }
            override fun onDiscoveryStopped(serviceType: String) {
                Log.d(TAG, "NSD discovery stopped for $serviceType")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                val name = serviceInfo.serviceName
                Log.d(TAG, "NSD service found: $name")
                val today = currentEpochDay()
                if (name == pseudonym(ownFingerprint, today) ||
                    name == pseudonym(ownFingerprint, today - 1)
                ) {
                    Log.d(TAG, "NSD ignoring own service")
                    return
                }
                // Only names matching a KNOWN contact's pseudonym are resolved —
                // strangers' (or spoofed-unknown) advertisements are ignored.
                val matchedFp = knownFingerprints().firstOrNull { fp ->
                    name == pseudonym(fp, today) || name == pseudonym(fp, today - 1)
                } ?: run {
                    Log.d(TAG, "NSD service $name matches no known contact — ignored")
                    return
                }
                Log.i(TAG, "NSD peer found: ${matchedFp.take(8)} — resolving")
                nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                        Log.w(TAG, "NSD resolve failed for ${matchedFp.take(8)}: errorCode=$errorCode")
                    }
                    override fun onServiceResolved(info: NsdServiceInfo) {
                        val host = info.host?.hostAddress ?: run {
                            Log.w(TAG, "NSD resolved but no host address for ${matchedFp.take(8)}")
                            return
                        }
                        Log.i(TAG, "NSD resolved: fp=${matchedFp.take(8)} at $host:${info.port}")
                        peerChannel.trySend(LanPeer(matchedFp, host, info.port))
                    }
                })
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "NSD service lost: ${serviceInfo.serviceName.take(8)}")
            }
        }

        nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
    }

    companion object {
        private const val TAG = "VoiceDrop/LAN"
        private const val SERVICE_TYPE = "_voicedrop._tcp"
        private const val PSEUDONYM_LABEL = "voicedrop/lan/v1"

        internal fun currentEpochDay(): Long = System.currentTimeMillis() / 86_400_000L

        internal fun pseudonym(fingerprintHex: String, epochDay: Long): String {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            md.update(PSEUDONYM_LABEL.toByteArray(Charsets.UTF_8))
            md.update(epochDay.toString().toByteArray(Charsets.UTF_8))
            md.update(fingerprintHex.toByteArray(Charsets.UTF_8))
            return "vd-" + md.digest().take(8).joinToString("") { "%02x".format(it) }
        }
    }
}
