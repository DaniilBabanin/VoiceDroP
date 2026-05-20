package com.voicedrop.service

import com.voicedrop.crypto.MessagePayload
import com.voicedrop.crypto.SentFrame
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.CancellationException
import java.io.File
import java.util.UUID

/**
 * Fan-out send helper: one opus blob written to disk once, N per-recipient
 * `encryptAndSend` calls, N `MessageEntity` rows all referencing the same path.
 *
 * Per-recipient failures (typically [com.voicedrop.crypto.AwaitingFirstReceive]
 * for a freshly paired contact, or transient ratchet errors) are logged via
 * the returned [SendResult] but do not abort the broadcast — the surviving
 * recipients still receive the message. If every recipient fails, the orphan
 * opus file is deleted.
 *
 * The class is intentionally framework-light (no Android imports) so it can
 * be unit-tested without spinning up [VoiceDropService].
 */
class MultiRecipientSender(
    private val messagesDir: File,
    private val encryptAndSend: suspend (
        contactId: String,
        plaintext: ByteArray,
        buildMessage: (frameUuidHex: String, frameUuidBytes: ByteArray, now: Long) -> MessageEntity?
    ) -> SentFrame,
) {

    data class SendResult(
        val successfulRecipientIds: List<String>,
        val failedRecipientIds: List<String>,
    )

    /**
     * Encrypts and sends [opusBytes] (wrapped in a [MessagePayload.encodeVoice]
     * KIND_VOICE frame) to every id in [recipientIds]. The on-disk opus path is
     * derived from a fresh UUID so the file is decoupled from any single
     * recipient's frame UUID — all per-recipient rows reference that same path.
     *
     * Returns a partition of recipients into success/failure lists, preserving
     * input order within each list.
     */
    suspend fun sendVoice(
        recipientIds: List<String>,
        opusBytes: ByteArray,
        durationMs: Int,
        deleteAfterMsByContact: Map<String, Long>,
    ): SendResult {
        if (recipientIds.isEmpty()) {
            return SendResult(emptyList(), emptyList())
        }

        messagesDir.mkdirs()
        // Use a fresh UUID for the shared filename; it does NOT have to equal any
        // wire-frame UUID (each recipient's row carries its own per-frame UUID).
        // Decoupling the file path from any single recipient's frame UUID keeps
        // refcount semantics straightforward.
        val sharedFile = File(messagesDir, "${UUID.randomUUID()}.opus")
        sharedFile.writeBytes(opusBytes)
        val sharedPath = sharedFile.absolutePath

        val successes = mutableListOf<String>()
        val failures = mutableListOf<String>()

        for (contactId in recipientIds) {
            // Payload bytes are identical across recipients — but we encode per
            // recipient because deleteAfterMs is per-contact (per the contact's
            // configured auto-delete window). If deleteAfterMs were uniform we
            // could encode once outside the loop.
            val deleteAfterMs = deleteAfterMsByContact[contactId] ?: 0L
            val payload = MessagePayload.encodeVoice(durationMs, deleteAfterMs, opusBytes)
            try {
                encryptAndSend(contactId, payload) { frameUuidHex, _, now ->
                    MessageEntity(
                        uuid = frameUuidHex,
                        contactId = contactId,
                        direction = MessageEntity.DIRECTION_OUTBOUND,
                        state = MessageEntity.STATE_SENT,
                        transport = TransportType.UNKNOWN,
                        encryptedFilePath = sharedPath,
                        durationMs = durationMs,
                        deleteAfterMs = deleteAfterMs,
                        scheduledDeleteAt = 0L,
                        transcription = null,
                        createdAt = now,
                        sentAt = now,
                        deliveredAt = 0L,
                        delivery_state = MessageEntity.DELIVERY_PENDING
                    )
                }
                successes.add(contactId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                failures.add(contactId)
            }
        }

        if (successes.isEmpty() && failures.isNotEmpty()) {
            // No surviving reference to the file — clean it up.
            sharedFile.delete()
        }

        return SendResult(successes, failures)
    }
}
