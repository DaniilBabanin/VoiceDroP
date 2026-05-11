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

class LanDiscovery(
    private val context: Context,
    private val ownFingerprint: String,
    private val contactFingerprints: Set<String>
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
            serviceName = ownFingerprint
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
                if (name == ownFingerprint) {
                    Log.d(TAG, "NSD ignoring own service")
                    return
                }
                if (name !in contactFingerprints) {
                    Log.d(TAG, "NSD unknown service (not a contact): ${name.take(8)}")
                    return
                }
                Log.i(TAG, "NSD contact found: ${name.take(8)} — resolving")
                nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                        Log.w(TAG, "NSD resolve failed for ${info.serviceName.take(8)}: errorCode=$errorCode")
                    }
                    override fun onServiceResolved(info: NsdServiceInfo) {
                        val host = info.host?.hostAddress ?: run {
                            Log.w(TAG, "NSD resolved but no host address for ${info.serviceName.take(8)}")
                            return
                        }
                        Log.i(TAG, "NSD resolved: fp=${info.serviceName.take(8)} at $host:${info.port}")
                        peerChannel.trySend(LanPeer(info.serviceName, host, info.port))
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
    }
}
