package com.voicedrop.network

import com.voicedrop.crypto.ChaCha20Poly1305Aead
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Wire format v2 codec (DR4). Pure binary — no ratchet state.
 *
 * Layout:
 *   frameLen:4 | frameKind:1 | senderFp:32 | recipFp:32 | dhPub:32 |
 *   pn:4 | n:4 | uuid:16 | timestampMs:8 | ciphertext:N
 *
 * AAD = entire header up to and including `timestampMs` = 133 bytes.
 * AEAD nonce = 12 zero bytes; safety rests on per-frame key uniqueness
 * (see plan/08-dr/00-overview.md §5).
 *
 * Tink's `subtle.ChaCha20Poly1305` prepends a random nonce and is therefore
 * the WRONG primitive here. [ChaCha20Poly1305Aead] (javax.crypto.Cipher with
 * the standard "ChaCha20-Poly1305" algorithm, API 28+) lets us pin nonce=0
 * to match the spec's wire shape; nonce-reuse safety rests on per-frame
 * key uniqueness (`mk` for DATA, `K_reset` for RESET).
 */
object FrameCodec {

    const val FRAME_KIND_DATA: Byte = 0x00
    const val FRAME_KIND_RESET: Byte = 0x01
    const val FRAME_KIND_RECEIPT: Byte = 0x02

    const val FRAME_LEN_BYTES = 4
    const val FRAME_KIND_BYTES = 1
    const val FP_BYTES = 32
    const val DH_PUB_BYTES = 32
    const val PN_BYTES = 4
    const val N_BYTES = 4
    const val UUID_BYTES = 16
    const val TIMESTAMP_BYTES = 8

    const val AAD_LEN =
        FRAME_LEN_BYTES + FRAME_KIND_BYTES + FP_BYTES + FP_BYTES + DH_PUB_BYTES +
            PN_BYTES + N_BYTES + UUID_BYTES + TIMESTAMP_BYTES  // 133

    // Bytes after `frameLen` that precede the ciphertext.
    const val HEADER_AFTER_LEN_BYTES = AAD_LEN - FRAME_LEN_BYTES  // 129

    const val AEAD_TAG_BYTES = 16

    private val ZERO_NONCE = ByteArray(12)

    // Well-known X25519 small-order / "low-order" points (libsodium blacklist).
    // High bit of byte[31] is irrelevant on Curve25519 (Tink masks it), so we
    // compare after masking it off and only store the 7 canonical encodings.
    private val LOW_ORDER_POINTS: Array<ByteArray> = arrayOf(
        ByteArray(32),  // 0 (order 1, identity)
        ByteArray(32).also { it[0] = 0x01 },  // 1 (order 4)
        byteArrayOf(
            0xe0.toByte(), 0xeb.toByte(), 0x7a.toByte(), 0x7c.toByte(),
            0x3b.toByte(), 0x41.toByte(), 0xb8.toByte(), 0xae.toByte(),
            0x16.toByte(), 0x56.toByte(), 0xe3.toByte(), 0xfa.toByte(),
            0xf1.toByte(), 0x9f.toByte(), 0xc4.toByte(), 0x6a.toByte(),
            0xda.toByte(), 0x09.toByte(), 0x8d.toByte(), 0xeb.toByte(),
            0x9c.toByte(), 0x32.toByte(), 0xb1.toByte(), 0xfd.toByte(),
            0x86.toByte(), 0x62.toByte(), 0x05.toByte(), 0x16.toByte(),
            0x5f.toByte(), 0x49.toByte(), 0xb8.toByte(), 0x00.toByte()
        ),
        byteArrayOf(
            0x5f.toByte(), 0x9c.toByte(), 0x95.toByte(), 0xbc.toByte(),
            0xa3.toByte(), 0x50.toByte(), 0x8c.toByte(), 0x24.toByte(),
            0xb1.toByte(), 0xd0.toByte(), 0xb1.toByte(), 0x55.toByte(),
            0x9c.toByte(), 0x83.toByte(), 0xef.toByte(), 0x5b.toByte(),
            0x04.toByte(), 0x44.toByte(), 0x5c.toByte(), 0xc4.toByte(),
            0x58.toByte(), 0x1c.toByte(), 0x8e.toByte(), 0x86.toByte(),
            0xd8.toByte(), 0x22.toByte(), 0x4e.toByte(), 0xdd.toByte(),
            0xd0.toByte(), 0x9f.toByte(), 0x11.toByte(), 0x57.toByte()
        ),
        ByteArray(32) { 0xff.toByte() }.also { it[0] = 0xec.toByte(); it[31] = 0x7f.toByte() },  // p - 1
        ByteArray(32) { 0xff.toByte() }.also { it[0] = 0xed.toByte(); it[31] = 0x7f.toByte() },  // p
        ByteArray(32) { 0xff.toByte() }.also { it[0] = 0xee.toByte(); it[31] = 0x7f.toByte() }   // p + 1
    )

    sealed class DecodeResult {
        data class Ok(val frame: DecodedFrame) : DecodeResult()
        data class Drop(val reason: DropReason) : DecodeResult()
    }

    enum class DropReason {
        FRAME_LEN_MISMATCH,
        UNKNOWN_FRAME_KIND,
        BAD_LAYOUT,
        ZERO_DH_PUB,
        LOW_ORDER_DH_PUB,

        /** RESET frame with non-zero bytes in the tail half of the dhPub slot (dr12 §6.1). */
        RESET_DH_PUB_TAIL_NONZERO,

        /** RESET frame with non-zero `pn` slot (dr12 §6.1 — slot unused on RESET). */
        RESET_PN_NONZERO
    }

    data class DecodedFrame(
        val kind: Byte,
        val senderFp: ByteArray,
        val recipFp: ByteArray,
        val dhPub: ByteArray,
        val pn: Int,
        val n: Int,
        val uuid: ByteArray,
        val timestampMs: Long,
        val ciphertext: ByteArray,
        /** Exact 133-byte AAD slice — feed directly to AEAD. */
        val aad: ByteArray
    )

    /**
     * Encode + seal a frame. Returns the full wire bytes including the 4-byte
     * `frameLen` prefix. Caller picks the AEAD key (`mk` for DATA/RECEIPT,
     * `K_reset` for RESET).
     *
     * For DATA / RECEIPT frames the caller is responsible for supplying a
     * valid (non-zero, non-low-order) `dhPub`. For RESET frames the spec
     * repurposes the slot as `resetNonce || zeros` — see [dr12].
     */
    fun encode(
        kind: Byte,
        senderFp: ByteArray,
        recipFp: ByteArray,
        dhPub: ByteArray,
        pn: Int,
        n: Int,
        uuid: ByteArray,
        timestampMs: Long,
        key: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        require(senderFp.size == FP_BYTES) { "senderFp must be $FP_BYTES bytes" }
        require(recipFp.size == FP_BYTES) { "recipFp must be $FP_BYTES bytes" }
        require(dhPub.size == DH_PUB_BYTES) { "dhPub must be $DH_PUB_BYTES bytes" }
        require(uuid.size == UUID_BYTES) { "uuid must be $UUID_BYTES bytes" }
        require(key.size == 32) { "AEAD key must be 32 bytes" }

        val ciphertextSize = plaintext.size + AEAD_TAG_BYTES
        val frameLen = HEADER_AFTER_LEN_BYTES + ciphertextSize

        val aad = ByteBuffer.allocate(AAD_LEN).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(frameLen)
            put(kind)
            put(senderFp)
            put(recipFp)
            put(dhPub)
            putInt(pn)
            putInt(n)
            put(uuid)
            putLong(timestampMs)
        }.array()

        val ciphertext = ChaCha20Poly1305Aead.encrypt(key, ZERO_NONCE, plaintext, aad)
        check(ciphertext.size == ciphertextSize) { "unexpected AEAD output size" }

        val wire = ByteArray(AAD_LEN + ciphertextSize)
        System.arraycopy(aad, 0, wire, 0, AAD_LEN)
        System.arraycopy(ciphertext, 0, wire, AAD_LEN, ciphertextSize)
        return wire
    }

    /**
     * Parse a delivered frame buffer. Validates structure only; AEAD-verification
     * is the caller's job because the key depends on ratchet state ([dr6]+).
     *
     * Drops happen BEFORE any X25519 op — required by the ratchet spec since the
     * receiver must not attempt scalar-mult on attacker-controlled junk.
     */
    fun decode(bytes: ByteArray): DecodeResult {
        if (bytes.size < AAD_LEN + AEAD_TAG_BYTES) {
            return DecodeResult.Drop(DropReason.BAD_LAYOUT)
        }
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        val frameLen = buf.int
        val expectedFrameLen = bytes.size - FRAME_LEN_BYTES
        if (frameLen != expectedFrameLen) {
            return DecodeResult.Drop(DropReason.FRAME_LEN_MISMATCH)
        }

        val kind = buf.get()
        if (kind != FRAME_KIND_DATA && kind != FRAME_KIND_RESET && kind != FRAME_KIND_RECEIPT) {
            return DecodeResult.Drop(DropReason.UNKNOWN_FRAME_KIND)
        }

        val senderFp = ByteArray(FP_BYTES).also { buf.get(it) }
        val recipFp = ByteArray(FP_BYTES).also { buf.get(it) }
        val dhPub = ByteArray(DH_PUB_BYTES).also { buf.get(it) }

        if (kind == FRAME_KIND_DATA || kind == FRAME_KIND_RECEIPT) {
            if (isAllZero(dhPub)) return DecodeResult.Drop(DropReason.ZERO_DH_PUB)
            if (isLowOrderX25519(dhPub)) return DecodeResult.Drop(DropReason.LOW_ORDER_DH_PUB)
        }

        val pn = buf.int
        val n = buf.int
        // Signed read of attacker bytes: a negative pn/n would surface as an
        // uncaught IllegalArgumentException in the ratchet (require(n >= 0)) —
        // remotely-triggerable crash. Drop structurally instead.
        if (pn < 0 || n < 0) return DecodeResult.Drop(DropReason.BAD_LAYOUT)
        val uuid = ByteArray(UUID_BYTES).also { buf.get(it) }
        val timestampMs = buf.long

        if (kind == FRAME_KIND_RESET) {
            // dhPub slot is repurposed as `resetNonce:16 || zeros:16` (dr12 §6.1).
            // Reject non-zero tail bytes — defense against future field-reuse confusion.
            for (i in 16 until DH_PUB_BYTES) {
                if (dhPub[i].toInt() != 0) {
                    return DecodeResult.Drop(DropReason.RESET_DH_PUB_TAIL_NONZERO)
                }
            }
            // The `pn` slot is unused on RESET; reject non-zero.
            if (pn != 0) return DecodeResult.Drop(DropReason.RESET_PN_NONZERO)
        }

        val ciphertextSize = bytes.size - AAD_LEN
        val ciphertext = ByteArray(ciphertextSize).also { buf.get(it) }

        val aad = bytes.copyOfRange(0, AAD_LEN)

        return DecodeResult.Ok(
            DecodedFrame(
                kind = kind,
                senderFp = senderFp,
                recipFp = recipFp,
                dhPub = dhPub,
                pn = pn,
                n = n,
                uuid = uuid,
                timestampMs = timestampMs,
                ciphertext = ciphertext,
                aad = aad
            )
        )
    }

    /**
     * Open the ciphertext of an already-decoded frame. Throws on AEAD failure.
     * Convenience for round-trip tests; production code in [dr8] performs the
     * clone-then-commit dance around this call.
     */
    fun decrypt(frame: DecodedFrame, key: ByteArray): ByteArray {
        require(key.size == 32) { "AEAD key must be 32 bytes" }
        return ChaCha20Poly1305Aead.decrypt(key, ZERO_NONCE, frame.ciphertext, frame.aad)
    }

    fun isAllZero(bytes: ByteArray): Boolean {
        var acc = 0
        for (b in bytes) acc = acc or (b.toInt() and 0xff)
        return acc == 0
    }

    /**
     * X25519 low-order point check. Exposed so the ratchet layer ([dr6]) can
     * apply belt-and-braces validation before any `computeSharedSecret` call.
     * Single source of truth: the small-order table lives only here.
     */
    fun isLowOrderX25519(dhPub: ByteArray): Boolean {
        // X25519 masks bit 255 of the public key on input. Compare after the
        // same mask so attacker-supplied high-bit flips don't slip past us.
        val masked = dhPub.copyOf()
        masked[31] = (masked[31].toInt() and 0x7f).toByte()
        for (point in LOW_ORDER_POINTS) {
            if (MessageDigest.isEqual(masked, point)) return true
        }
        return false
    }
}
