package com.voicedrop

import android.app.Application
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.voicedrop.service.AutoDeleteWorker
import eu.buney.kopus.OpusLoader

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // Workaround for kopus 1.6.1.2: OpusDecoder calls nativeCreate before its
        // init block runs OpusLoader.load(), so the first decoder on a fresh process
        // (e.g. receiving audio before recording any) crashes with UnsatisfiedLinkError.
        OpusLoader.load()
        AeadConfig.register()
        HybridConfig.register()
        AutoDeleteWorker.schedule(this)
    }
}
