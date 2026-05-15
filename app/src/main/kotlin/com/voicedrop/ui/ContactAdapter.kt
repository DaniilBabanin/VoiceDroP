package com.voicedrop.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.voicedrop.R
import com.voicedrop.storage.ActiveContactsPrefs
import com.voicedrop.storage.ContactEntity

class ContactAdapter(
    private val onContactClick: (String) -> Unit
) : ListAdapter<ContactEntity, ContactAdapter.ViewHolder>(DIFF_CALLBACK) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return ViewHolder(view, this)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val contact = getItem(position)
        holder.bind(contact, currentList)
        holder.itemView.setOnClickListener { onContactClick(contact.id) }
    }

    fun refreshActiveTicks() {
        notifyDataSetChanged()
    }

    class ViewHolder(view: View, private val adapter: ContactAdapter) :
        RecyclerView.ViewHolder(view) {
        private val nameText: TextView = view.findViewById(R.id.text_contact_name)
        private val checkbox: CheckBox = view.findViewById(R.id.checkbox_active)

        fun bind(contact: ContactEntity, all: List<ContactEntity>) {
            val ctx = itemView.context
            nameText.text = contact.name

            // Tick reflects the explicit default; falls back to "newest" only when unset,
            // so a fresh install with one contact still shows it ticked.
            val resolved = ActiveContactsPrefs.resolveRecipient(ctx, all)
            val isChecked = resolved?.id == contact.id

            checkbox.setOnCheckedChangeListener(null)
            checkbox.isChecked = isChecked
            checkbox.setOnCheckedChangeListener { _, checked ->
                ActiveContactsPrefs.setDefaultId(ctx, if (checked) contact.id else null)
                adapter.refreshActiveTicks()
            }
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ContactEntity>() {
            override fun areItemsTheSame(a: ContactEntity, b: ContactEntity) = a.id == b.id
            override fun areContentsTheSame(a: ContactEntity, b: ContactEntity) = a == b
        }
    }
}
