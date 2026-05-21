package com.voicedrop.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.voicedrop.R
import com.voicedrop.storage.ActiveContactsPrefs

class ContactAdapter(
    private val onContactClick: (String) -> Unit
) : ListAdapter<ContactRowUiState, ContactAdapter.ViewHolder>(DIFF_CALLBACK) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val state = getItem(position)
        holder.bind(state)
        holder.itemView.setOnClickListener { onContactClick(state.id) }
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val avatar: ImageView = view.findViewById(R.id.image_avatar)
        private val nameText: TextView = view.findViewById(R.id.text_contact_name)
        private val previewText: TextView = view.findViewById(R.id.text_preview)
        private val timestampText: TextView = view.findViewById(R.id.text_timestamp)
        private val badge: TextView = view.findViewById(R.id.badge_count)
        private val checkbox: CheckBox = view.findViewById(R.id.checkbox_active)

        fun bind(state: ContactRowUiState) {
            val ctx = itemView.context
            avatar.setImageDrawable(state.avatarDrawable)
            nameText.text = state.name
            previewText.text = state.previewText
            timestampText.text = state.timestampText
            timestampText.visibility = if (state.timestampText.isEmpty()) View.GONE else View.VISIBLE

            if (state.badgeCount > 0) {
                badge.visibility = View.VISIBLE
                badge.text = if (state.badgeCount > 99) "99+" else state.badgeCount.toString()
            } else {
                badge.visibility = View.GONE
            }

            // Multi-select: tick reflects this contact's membership in the persisted set.
            // Null the listener before mutating the checked state so recycled views
            // don't fire a spurious onCheckedChanged with the previous row's id.
            checkbox.setOnCheckedChangeListener(null)
            checkbox.isChecked = state.isActive
            checkbox.setOnCheckedChangeListener { _, checked ->
                ActiveContactsPrefs.setActive(ctx, state.id, checked)
            }
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ContactRowUiState>() {
            override fun areItemsTheSame(a: ContactRowUiState, b: ContactRowUiState) = a.id == b.id

            // Drawable equality is reference-based and would force needless rebinds
            // when AvatarFactory's LRU returns the cached drawable for the same id.
            // Compare on the render-driving scalars instead.
            override fun areContentsTheSame(a: ContactRowUiState, b: ContactRowUiState): Boolean =
                a.name == b.name &&
                    a.previewText.toString() == b.previewText.toString() &&
                    a.timestampText == b.timestampText &&
                    a.badgeCount == b.badgeCount &&
                    a.isActive == b.isActive
        }
    }
}
