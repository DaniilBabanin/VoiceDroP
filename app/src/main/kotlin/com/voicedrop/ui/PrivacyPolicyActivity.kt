package com.voicedrop.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.MenuItem
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.voicedrop.R
import io.noties.markwon.Markwon
import io.noties.markwon.ext.tables.TablePlugin
import io.noties.markwon.linkify.LinkifyPlugin

class PrivacyPolicyActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy_policy)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        EdgeToEdgeSetup.apply(this)
        EdgeToEdgeSetup.applyTopInset(toolbar)
        EdgeToEdgeSetup.applyBottomInset(findViewById(R.id.scroll_privacy))

        val textView = findViewById<TextView>(R.id.text_privacy_policy)

        val source = try {
            assets.open(PRIVACY_ASSET).use { stream ->
                stream.bufferedReader(Charsets.UTF_8).readText()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read $PRIVACY_ASSET from assets", e)
            getString(R.string.privacy_policy_load_failed)
        }

        val markwon = Markwon.builder(this)
            .usePlugin(TablePlugin.create(this))
            .usePlugin(LinkifyPlugin.create())
            .build()
        markwon.setMarkdown(textView, source)

        findViewById<Button>(R.id.button_view_on_github).setOnClickListener {
            val url = getString(R.string.privacy_policy_url)
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(this, url, Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    companion object {
        private const val TAG = "VoiceDrop/Privacy"
        private const val PRIVACY_ASSET = "PRIVACY.md"
    }
}
