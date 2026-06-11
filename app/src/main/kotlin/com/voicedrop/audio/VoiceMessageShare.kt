package com.voicedrop.audio

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Decodes a stored `.opus` voice message into a `.wav` for the system share
 * sheet. DR17.5 cutover (decision 2b): audio is plaintext on disk — trusts
 * Android FS encryption, drops the v1 ECDH-AEAD-at-rest envelope.
 */
object VoiceMessageShare {

    private const val SAMPLE_RATE = 16000
    private const val CHANNELS = 1
    private const val BITS_PER_SAMPLE = 16

    suspend fun prepare(context: Context, uuid: String): File? = withContext(Dispatchers.IO) {
        val db = AppDatabase.getInstance(context)
        val repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        val message = repository.getMessage(uuid) ?: return@withContext null
        val opusPath = message.encryptedFilePath ?: return@withContext null
        val opusFile = File(opusPath)
        if (!opusFile.exists()) return@withContext null

        val opusStream = opusFile.readBytes()

        val shareDir = File(context.cacheDir, "share").apply { mkdirs() }
        // Drop any stale WAVs from prior shares — the chooser target may still hold a grant,
        // but a new long-press should always export fresh. Secure wipe: these are
        // fully-decoded plaintext audio. AutoDeleteWorker sweeps the dir too.
        shareDir.listFiles()?.forEach { MessageRepository.secureDelete(it) }

        val outFile = File(shareDir, "voicedrop-${uuid}.wav")
        writeWav(opusStream, outFile)
        outFile
    }

    fun share(context: Context, file: File) {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        shareUri(context, uri)
    }

    internal fun shareUri(context: Context, uri: Uri) {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "audio/wav"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(sendIntent, null).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            // Required when launched from a non-Activity context (e.g. notification receiver).
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(chooser)
    }

    private fun writeWav(opusStream: ByteArray, outFile: File) {
        val decoder = OpusDecoder().apply { init(SAMPLE_RATE, CHANNELS) }
        try {
            RandomAccessFile(outFile, "rw").use { raf ->
                raf.setLength(0)
                // Reserve 44 bytes for the header; back-patch sizes after writing data.
                raf.write(ByteArray(44))

                var pcmBytes = 0L
                val buf = ByteBuffer.wrap(opusStream).order(ByteOrder.LITTLE_ENDIAN)
                while (buf.remaining() >= 4) {
                    val len = buf.int
                    if (len <= 0 || len > buf.remaining()) break
                    val packet = ByteArray(len)
                    buf.get(packet)
                    val pcm = decoder.decode(packet)
                    val pcmByteBuf = ByteBuffer.allocate(pcm.size * 2).order(ByteOrder.LITTLE_ENDIAN)
                    for (s in pcm) pcmByteBuf.putShort(s)
                    raf.write(pcmByteBuf.array())
                    pcmBytes += pcm.size * 2
                }

                writeWavHeader(raf, pcmBytes.toInt())
            }
        } finally {
            decoder.release()
        }
    }

    private fun writeWavHeader(raf: RandomAccessFile, pcmBytes: Int) {
        val byteRate = SAMPLE_RATE * CHANNELS * BITS_PER_SAMPLE / 8
        val blockAlign = CHANNELS * BITS_PER_SAMPLE / 8
        val header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
        header.put("RIFF".toByteArray(Charsets.US_ASCII))
        header.putInt(36 + pcmBytes)
        header.put("WAVE".toByteArray(Charsets.US_ASCII))
        header.put("fmt ".toByteArray(Charsets.US_ASCII))
        header.putInt(16)                     // PCM fmt chunk size
        header.putShort(1)                    // PCM format
        header.putShort(CHANNELS.toShort())
        header.putInt(SAMPLE_RATE)
        header.putInt(byteRate)
        header.putShort(blockAlign.toShort())
        header.putShort(BITS_PER_SAMPLE.toShort())
        header.put("data".toByteArray(Charsets.US_ASCII))
        header.putInt(pcmBytes)

        raf.seek(0)
        raf.write(header.array())
    }
}
