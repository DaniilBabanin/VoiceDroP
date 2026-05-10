package com.voicedrop.ui

import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.view.Window
import android.view.WindowManager
import android.widget.ArrayAdapter
import android.widget.ListView
import com.voicedrop.R
import com.voicedrop.storage.ContactEntity

class ContactPickerDialog(
    context: Context,
    private val contacts: List<ContactEntity>,
    private val onContactSelected: (String) -> Unit
) : Dialog(context) {

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
        } else {
            val adapter = ArrayAdapter(
                context,
                android.R.layout.simple_list_item_1,
                contacts.map { it.name }
            )
            listView.adapter = adapter
            listView.setOnItemClickListener { _, _, position, _ ->
                onContactSelected(contacts[position].id)
                dismiss()
            }
        }
    }
}
