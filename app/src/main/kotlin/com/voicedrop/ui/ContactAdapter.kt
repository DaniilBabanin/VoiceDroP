package com.voicedrop.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.voicedrop.R
import com.voicedrop.storage.ContactEntity

class ContactAdapter(
    private val onContactClick: (String) -> Unit
) : ListAdapter<ContactEntity, ContactAdapter.ViewHolder>(DIFF_CALLBACK) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val contact = getItem(position)
        holder.bind(contact)
        holder.itemView.setOnClickListener { onContactClick(contact.id) }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val nameText: TextView = view.findViewById(R.id.text_contact_name)

        fun bind(contact: ContactEntity) {
            nameText.text = contact.name
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ContactEntity>() {
            override fun areItemsTheSame(a: ContactEntity, b: ContactEntity) = a.id == b.id
            override fun areContentsTheSame(a: ContactEntity, b: ContactEntity) = a == b
        }
    }
}
