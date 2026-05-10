package com.voicedrop.service

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageEntity
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
        processOutboxExpiry(repository)

        return Result.success()
    }

    private suspend fun processAutoDeletes(
        repository: MessageRepository,
        notificationHelper: NotificationHelper
    ) {
        val now = System.currentTimeMillis()
        val scheduled = repository.getScheduledDeletes(now)
        for (message in scheduled) {
            message.encryptedFilePath?.let { path ->
                secureDelete(File(path))
            }
            repository.markDeleted(message.uuid)
            notificationHelper.cancelNotification(message.uuid.hashCode())
        }
    }

    private suspend fun processOutboxExpiry(repository: MessageRepository) {
        val sevenDaysAgo = System.currentTimeMillis() - OUTBOX_MAX_AGE_MS
        val expired = repository.getExpiredPendingActions(sevenDaysAgo)

        for (action in expired) {
            repository.deletePendingAction(action.id)
            val messages = repository.getExpiredOutbox(sevenDaysAgo)
            for (message in messages) {
                if (message.contactId == action.contactId) {
                    repository.updateMessageState(message.uuid, MessageEntity.STATE_UNDELIVERABLE)
                }
            }
        }
    }

    private fun secureDelete(file: File) {
        if (!file.exists()) return
        try {
            val length = file.length()
            if (length > 0) {
                file.outputStream().use { out ->
                    val zeros = ByteArray(minOf(length, 65536).toInt())
                    var remaining = length
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, zeros.size.toLong()).toInt()
                        out.write(zeros, 0, toWrite)
                        remaining -= toWrite
                    }
                }
            }
        } finally {
            file.delete()
        }
    }

    companion object {
        private const val OUTBOX_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000
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
