package com.voicedrop.crypto

/**
 * §3.1 — 256-entry emoji palette indexed by byte value. Consumed by [Sas.codeFor]
 * to map HMAC output bytes to glyphs. Lives in `crypto/` (not `ui/`) so the
 * dependency arrow points outward: UI may depend on crypto, never the reverse.
 */
object SasEmojiPalette {
    val EMOJI_PALETTE = arrayOf(
        "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
        "🐧","🐦","🐤","🦆","🦅","🦉","🦇","🐺","🐗","🐴","🦄","🐝","🐛","🦋","🐌","🐞",
        "🐜","🦟","🦗","🕷","🦂","🐢","🐍","🦎","🦖","🦕","🐙","🦑","🦐","🦞","🦀","🐡",
        "🐠","🐟","🐬","🐳","🐋","🦈","🐊","🐅","🐆","🦓","🦍","🦧","🦣","🐘","🦛","🦏",
        "🐪","🐫","🦒","🦘","🦬","🐃","🐂","🐄","🐎","🐖","🐏","🐑","🦙","🐐","🦌","🐕",
        "🐩","🦮","🐕‍🦺","🐈","🐈‍⬛","🪶","🐓","🦃","🦤","🦚","🦜","🦢","🦩","🕊","🐇","🦝",
        "🦨","🦡","🦫","🦦","🦥","🐁","🐀","🐿","🦔","🐾","🐉","🐲","🌵","🎄","🌲","🌳",
        "🌴","🌱","🌿","☘","🍀","🎍","🎋","🍃","🍂","🍁","🍄","🌾","💐","🌷","🌹","🥀",
        "🌺","🌸","🌼","🌻","🌞","🌝","🌛","🌜","🌚","🌕","🌖","🌗","🌘","🌑","🌒","🌓",
        "🌔","🌙","🌟","⭐","🌠","🌌","☁","⛅","🌤","🌈","⚡","❄","🌊","💧","🔥","🌪",
        "🎃","🎄","🎆","🎇","🧨","✨","🎉","🎊","🎈","🎁","🎀","🎗","🎟","🎫","🏆","🥇",
        "🥈","🥉","🏅","🎖","🏵","🎗","🎭","🎨","🎬","🎤","🎧","🎼","🎹","🥁","🎷","🎺",
        "🎸","🪕","🎻","🎲","♟","🎯","🎳","🎮","🎰","🧩","🚗","🚕","🚙","🚌","🚎","🏎",
        "🚓","🚑","🚒","🚐","🛻","🚚","🚛","🚜","🏍","🛵","🚲","🛴","🛹","🛺","🚁","🛸",
        "🚀","✈","🚂","🚆","🚇","🚈","🚉","🚊","🚋","🚝","🚞","🚍","🚟","🚠","🚡","⛵",
        "🚤","🛥","🛳","⛴","🚢","🗺","🏔","⛰","🌋","🗻","🏕","🏖","🏜","🏝","🏞","🏟"
    )

    /**
     * Maps the first [count] bytes of [bytes] to palette emoji. No default — every
     * caller must declare its bit budget so a future caller cannot silently pick up
     * the v1.2.0.12 4-emoji (32-bit) shape.
     */
    fun getEmojisForBytes(bytes: ByteArray, count: Int): List<String> {
        require(bytes.size >= count) { "Need at least $count bytes" }
        return bytes.take(count).map { b ->
            EMOJI_PALETTE[b.toInt() and 0xFF]
        }
    }
}
