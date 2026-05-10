package com.voicedrop

import android.app.Application
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.voicedrop.service.AutoDeleteWorker

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        AeadConfig.register()
        HybridConfig.register()
        AutoDeleteWorker.schedule(this)
    }
}
