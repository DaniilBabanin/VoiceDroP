package com.voicedrop.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * DR17.5 §"Inner-plaintext schema" — the application-level message wrapped by
 * the ratchet AEAD. Layout:
 *
 * ```
 * [kind:1][...kind-specific bytes...]
 *
 * kind = 0x00  VOICE   → [durationMs:4][deleteAfterMs:8][opusBytes:N]
 * kind = 0x01  HELLO   → []                                          ← bootstrap sentinel
 * kind = 0x02  DELETE  → [targetUuid:16]
 * kind = 0x03  PLAYED  → [targetUuid:16]                             ← spec 16-played-receipt.md
 * ```
 *
 * Forward-compat contract (locked in by v1.2.0.0): a receiver that sees an
 * unknown `kind` MUST still allow the ratchet path to enqueue its RECEIPT, then
 * drop the inner plaintext silently (see dr17.5 §"Forward compatibility"). This
 * codec returns [Parsed.Unknown] for those; the dispatcher logs + drops.
 *
 * The kind dispatch lives at the **inner** layer only — `FrameCodec` still sees
 * wire-level DATA / RECEIPT / RESET. No `FrameCodec` change in this phase.
 */
object MessagePayload {

    const val KIND_VOICE: Byte = 0x00
    const val KIND_HELLO: Byte = 0x01
    const val KIND_DELETE: Byte = 0x02
    const val KIND_PLAYED: Byte = 0x03

    private const val KIND_BYTES = 1
    private const val DURATION_BYTES = 4
    private const val DELETE_AFTER_BYTES = 8
    private const val UUID_BYTES = 16

    private const val VOICE_HEADER_BYTES = KIND_BYTES + DURATION_BYTES + DELETE_AFTER_BYTES
    private const val HELLO_BYTES = KIND_BYTES
    private const val DELETE_BYTES = KIND_BYTES + UUID_BYTES
    private const val PLAYED_BYTES = KIND_BYTES + UUID_BYTES   // 17, same shape as DELETE

    sealed class Parsed {
        data class Voice(val durationMs: Int, val deleteAfterMs: Long, val opusBytes: ByteArray) : Parsed() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Voice) return false
                return durationMs == other.durationMs &&
                    deleteAfterMs == other.deleteAfterMs &&
                    opusBytes.contentEquals(other.opusBytes)
            }
            override fun hashCode(): Int {
                var r = durationMs
                r = 31 * r + deleteAfterMs.hashCode()
                r = 31 * r + opusBytes.contentHashCode()
                return r
            }
        }
        object Hello : Parsed()
        data class Delete(val targetUuid: UUID) : Parsed()
        data class Played(val targetUuid: UUID) : Parsed()
        /** Unknown kind. Per the forward-compat contract: dispatcher MUST drop silently after RECEIPT enqueue. */
        data class Unknown(val kind: Int, val bodyLen: Int) : Parsed()
    }

    fun encodeVoice(durationMs: Int, deleteAfterMs: Long, opusBytes: ByteArray): ByteArray =
        ByteBuffer.allocate(VOICE_HEADER_BYTES + opusBytes.size).order(ByteOrder.BIG_ENDIAN).apply {
            put(KIND_VOICE)
            putInt(durationMs)
            putLong(deleteAfterMs)
            put(opusBytes)
        }.array()

    fun encodeHello(): ByteArray = byteArrayOf(KIND_HELLO)

    fun encodeDelete(targetUuid: UUID): ByteArray =
        ByteBuffer.allocate(DELETE_BYTES).order(ByteOrder.BIG_ENDIAN).apply {
            put(KIND_DELETE)
            putLong(targetUuid.mostSignificantBits)
            putLong(targetUuid.leastSignificantBits)
        }.array()

    fun encodePlayed(targetUuid: UUID): ByteArray =
        ByteBuffer.allocate(PLAYED_BYTES).order(ByteOrder.BIG_ENDIAN).apply {
            put(KIND_PLAYED)
            putLong(targetUuid.mostSignificantBits)
            putLong(targetUuid.leastSignificantBits)
        }.array()

    fun parse(bytes: ByteArray): Parsed {
        if (bytes.isEmpty()) throw InvalidPayload("payload empty")
        val kind = bytes[0]
        val body = bytes.size - KIND_BYTES
        return when (kind) {
            KIND_VOICE -> {
                if (body < DURATION_BYTES + DELETE_AFTER_BYTES) {
                    throw InvalidPayload("VOICE truncated: bodyLen=$body")
                }
                val buf = ByteBuffer.wrap(bytes, KIND_BYTES, body).order(ByteOrder.BIG_ENDIAN)
                val durationMs = buf.int
                val deleteAfterMs = buf.long
                val opusLen = body - DURATION_BYTES - DELETE_AFTER_BYTES
                val opus = ByteArray(opusLen).also { if (opusLen > 0) buf.get(it) }
                Parsed.Voice(durationMs, deleteAfterMs, opus)
            }
            KIND_HELLO -> {
                if (bytes.size != HELLO_BYTES) throw InvalidPayload("HELLO size=${bytes.size} != $HELLO_BYTES")
                Parsed.Hello
            }
            KIND_DELETE -> {
                if (bytes.size != DELETE_BYTES) throw InvalidPayload("DELETE size=${bytes.size} != $DELETE_BYTES")
                val buf = ByteBuffer.wrap(bytes, KIND_BYTES, UUID_BYTES).order(ByteOrder.BIG_ENDIAN)
                Parsed.Delete(UUID(buf.long, buf.long))
            }
            KIND_PLAYED -> {
                if (bytes.size != PLAYED_BYTES) throw InvalidPayload("PLAYED size=${bytes.size} != $PLAYED_BYTES")
                val buf = ByteBuffer.wrap(bytes, KIND_BYTES, UUID_BYTES).order(ByteOrder.BIG_ENDIAN)
                Parsed.Played(UUID(buf.long, buf.long))
            }
            else -> Parsed.Unknown(kind.toInt() and 0xff, body)
        }
    }
}

class InvalidPayload(reason: String) : RuntimeException("MessagePayload: $reason")
