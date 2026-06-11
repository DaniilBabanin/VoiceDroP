package com.voicedrop.service

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import java.io.File
import java.util.concurrent.TimeUnit

class AutoDeleteWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val db = AppDatabase.getInstance(applicationContext)
        val repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
        val notificationHelper = NotificationHelper(applicationContext)

        processAutoDeletes(repository, notificationHelper)
        sweepShareCache()
        sweepOrphanOpusBlobs(repository)

        return Result.success()
    }

    private suspend fun processAutoDeletes(
        repository: MessageRepository,
        notificationHelper: NotificationHelper
    ) {
        val now = System.currentTimeMillis()
        val scheduled = repository.getScheduledDeletes(now)
        for (message in scheduled) {
            // Refcount-aware: shared fan-out blobs are preserved until the
            // last recipient's row is deleted.
            repository.markDeletedWithBlobRefcount(message)
            notificationHelper.cancelNotification(message.uuid.hashCode())
        }
    }

    /**
     * Shared WAVs in `cacheDir/share` are fully-decoded plaintext audio that
     * otherwise outlive the original message's auto-delete and secure wipe.
     * Wipe anything past the grace window (chooser grant long consumed).
     */
    private fun sweepShareCache() {
        val cutoff = System.currentTimeMillis() - SWEEP_GRACE_MS
        File(applicationContext.cacheDir, "share").listFiles()?.forEach { f ->
            if (f.lastModified() < cutoff) MessageRepository.secureDelete(f)
        }
    }

    /**
     * A crash between blob write and row insert (MultiRecipientSender writes the
     * opus before any row exists) leaves a plaintext file referenced by nothing.
     * Sweep zero-refcount blobs, with a grace window so an in-flight send isn't
     * wiped between file write and row commit.
     */
    private suspend fun sweepOrphanOpusBlobs(repository: MessageRepository) {
        val cutoff = System.currentTimeMillis() - SWEEP_GRACE_MS
        val dir = File(applicationContext.filesDir, "messages")
        dir.listFiles { f: File -> f.extension == "opus" }?.forEach { f ->
            if (f.lastModified() < cutoff && repository.countReferencesToFile(f.absolutePath) == 0) {
                MessageRepository.secureDelete(f)
            }
        }
    }

    companion object {
        private const val SWEEP_GRACE_MS = 60L * 60 * 1000
        private const val WORK_NAME = "auto_delete"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<AutoDeleteWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
