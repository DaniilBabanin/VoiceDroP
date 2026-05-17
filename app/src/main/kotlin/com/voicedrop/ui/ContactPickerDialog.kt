package com.voicedrop.ui

import android.app.Dialog
import android.content.Context
import android.graphics.Color
import android.os.Bundle
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.TextView
import com.voicedrop.R
import com.voicedrop.storage.ContactEntity

/**
 * DR17.5 W4 — when [ContactEntity.dhr_pub] IS NULL the contact's ratchet hasn't
 * learned the peer's DH public yet (Bob has just paired, Alice hasn't sent her
 * first DATA), so `RatchetEncryptAndSend` would throw `AwaitingFirstReceive`.
 * Per dr17.5 §"Bob's can't-send-first UX" the row is silently disabled in the
 * picker — no caption, no banner. In normal pairing Alice's auto-HELLO arrives
 * in <1s and the disabled state lifts before the user notices.
 */
class ContactPickerDialog(
    context: Context,
    private val contacts: List<ContactEntity>,
    private val onContactSelected: (String) -> Unit
) : Dialog(ContextThemeWrapper(context, R.style.Theme_VoiceDrop)) {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.dialog_contact_picker)

        window?.addFlags(
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD
        )

        val listView = findViewById<ListView>(R.id.contact_list)
        if (contacts.isEmpty()) {
            val adapter = ArrayAdapter(
                context,
                android.R.layout.simple_list_item_1,
                listOf("No contacts — tap to pair")
            )
            listView.adapter = adapter
            return
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
                if (contacts[position].dhr_pub == null) {
                    // Grey out: setEnabled also covers the alpha state on most themes.
                    view.isEnabled = false
                    text1.isEnabled = false
                    text1.setTextColor(Color.GRAY)
                } else {
                    view.isEnabled = true
                    text1.isEnabled = true
                }
                return view
            }
        }
        listView.adapter = adapter
        listView.setOnItemClickListener { _, _, position, _ ->
            onContactSelected(contacts[position].id)
            dismiss()
        }
    }
}
