package com.voicedrop.storage

enum class TransportType(val value: Int) {
    UNKNOWN(0),
    LAN(1),
    P2P(2),
    RELAY(3),
    WEBRTC(4);

    companion object {
        fun fromInt(value: Int): TransportType =
            entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}
