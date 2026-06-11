package com.voicedrop.ui

import android.app.AlertDialog
import android.content.Context
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.widget.TextView
import com.voicedrop.R
import com.voicedrop.crypto.Sas
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactDao
import com.voicedrop.storage.isVerifiedAgainst
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * §3.1 — Identity-verification dialog. Single-sided: tapping "Mark as verified"
 * writes `verified_at` for this device only. No frame is sent; verification is
 * meaningful only via an out-of-band channel between humans.
 *
 * The caller MUST pass a `scope` tied to its own lifecycle (e.g. the activity's
 * `scope` field cancelled in `onDestroy`). The dialog launches DB I/O and UI
 * refresh coroutines off this scope; on activity destruction, the scope's cancel
 * propagates and the in-flight `dialog.getButton(...)` calls never fire on a
 * destroyed window.
 */
class VerifyIdentityDialog(
    private val context: Context,
    private val contactId: String,
    private val myIdPub: ByteArray,
    private val theirIdPub: ByteArray,
    private val scope: CoroutineScope,
    private val contactDao: ContactDao =
        AppDatabase.getInstance(context).contactDao(),
) {

    fun show() {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_verify_identity, null)
        val emojiText = view.findViewById<TextView>(R.id.verify_dialog_emojis)
        val statusText = view.findViewById<TextView>(R.id.verify_dialog_status)

        emojiText.text = Sas.codeFor(myIdPub, theirIdPub).joinToString(" ")

        val dialog = AlertDialog.Builder(context)
            .setTitle(R.string.verify_identity_title)
            .setView(view)
            .setNegativeButton(R.string.verify_identity_button_close, null)
            .setPositiveButton(" ", null) // label set in refresh()
            .create()

        dialog.setOnShowListener { refresh(dialog, statusText) }
        // SAS ceremony: dialogs get their own window — block capture here too.
        dialog.window?.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE
        )
        dialog.show()
    }

    private fun refresh(dialog: AlertDialog, statusText: TextView) {
        scope.launch {
            val contact = withContext(Dispatchers.IO) { contactDao.getById(contactId) }
            val verified = contact?.isVerifiedAgainst(myIdPub, theirIdPub) == true
            val positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            if (verified) {
                val whenStr = DateUtils.getRelativeTimeSpanString(
                    contact!!.verified_at!!,
                    System.currentTimeMillis(),
                    DateUtils.DAY_IN_MILLIS,
                ).toString()
                statusText.text = context.getString(R.string.verify_identity_status_verified, whenStr)
                positive.text = context.getString(R.string.verify_identity_button_clear)
                positive.setOnClickListener {
                    scope.launch {
                        withContext(Dispatchers.IO) { contactDao.clearVerified(contactId) }
                        refresh(dialog, statusText)
                    }
                }
            } else {
                statusText.text = context.getString(R.string.verify_identity_status_unverified)
                positive.text = context.getString(R.string.verify_identity_button_mark)
                positive.setOnClickListener {
                    scope.launch {
                        val hash = Sas.fpPairBinding(myIdPub, theirIdPub)
                        withContext(Dispatchers.IO) {
                            contactDao.setVerified(contactId, System.currentTimeMillis(), hash)
                        }
                        refresh(dialog, statusText)
                    }
                }
            }
        }
    }
}
