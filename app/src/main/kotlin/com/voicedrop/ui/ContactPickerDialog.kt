package com.voicedrop.ui

import android.content.Context
import android.graphics.Typeface
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.voicedrop.R
import com.voicedrop.storage.ContactEntity

/**
 * DR17.5 W4 — when [ContactEntity.dhr_pub] IS NULL the contact's ratchet hasn't
 * learned the peer's DH public yet (Bob has just paired, Alice hasn't sent her
 * first DATA), so `RatchetEncryptAndSend` would throw `AwaitingFirstReceive`.
 * Per dr17.5 §"Bob's can't-send-first UX" the row is silently disabled in the
 * picker — no caption, no banner. In normal pairing Alice's auto-HELLO arrives
 * in <1s and the disabled state lifts before the user notices.
 *
 * v1.x visual refresh — wraps MaterialAlertDialogBuilder. The custom ArrayAdapter
 * preserves the visual-disabled treatment that setItems() can't express.
 */
object ContactPickerDialog {

    /** Returns a configured AlertDialog. Caller is responsible for show()/dismiss(). */
    operator fun invoke(
        context: Context,
        contacts: List<ContactEntity>,
        onContactSelected: (String) -> Unit
    ): AlertDialog {
        if (contacts.isEmpty()) {
            return MaterialAlertDialogBuilder(context)
                .setTitle(R.string.select_contact)
                .setMessage(R.string.widget_empty_hint)
                .setPositiveButton(android.R.string.ok, null)
                .create()
                .applyShowWhenLocked()
        }

        val adapter = object : ArrayAdapter<ContactEntity>(
            context,
            android.R.layout.simple_list_item_1,
            contacts
        ) {
            override fun isEnabled(position: Int): Boolean =
                contacts[position].dhr_pub != null
            override fun areAllItemsEnabled(): Boolean =
                contacts.all { it.dhr_pub != null }
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = super.getView(position, convertView, parent)
                val text1 = view.findViewById<TextView>(android.R.id.text1)
                text1.text = contacts[position].name
                text1.typeface = Typeface.create("sans-serif", Typeface.NORMAL)
                val enabled = contacts[position].dhr_pub != null
                view.isEnabled = enabled
                text1.isEnabled = enabled
                text1.alpha = if (enabled) 1.0f else 0.4f
                return view
            }
        }

        return MaterialAlertDialogBuilder(context)
            .setTitle(R.string.select_contact)
            .setAdapter(adapter) { dialog, which ->
                if (contacts[which].dhr_pub != null) {
                    onContactSelected(contacts[which].id)
                }
                dialog.dismiss()
            }
            .create()
            .applyShowWhenLocked()
    }

    private fun AlertDialog.applyShowWhenLocked(): AlertDialog {
        window?.addFlags(
            android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            android.view.WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD
        )
        return this
    }
}
