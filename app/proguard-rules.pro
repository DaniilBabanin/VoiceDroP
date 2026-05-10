# VoiceDrop ProGuard rules

# Keep Kotlin metadata for reflection and serialization
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes SourceFile,LineNumberTable
-keepattributes Exceptions

# Keep kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class com.voicedrop.**$$serializer { *; }
-keepclassmembers class com.voicedrop.** {
    *** Companion;
}
-keepclasseswithmembers class com.voicedrop.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep Signal classes for OkHttp WebSocket + kotlinx.serialization
-keep class com.voicedrop.network.SignalingClient$Signal { *; }
-keep class com.voicedrop.network.SignalingClient$Signal$* { *; }

# Room — keep all entities and DAOs
-keep class com.voicedrop.storage.** { *; }
-keepclassmembers class * extends androidx.room.RoomDatabase { abstract *; }

# Google Tink — keep all crypto primitives
-keep class com.google.crypto.tink.** { *; }
-dontwarn com.google.crypto.tink.**

# kopus / libopus JNI — keep native method bindings
-keep class eu.buney.kopus.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# ZXing barcode scanner
-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.barcodescanner.** { *; }

# OkHttp
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# WorkManager
-keep class * extends androidx.work.Worker
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context,androidx.work.WorkerParameters);
}

# Keep our Service, BroadcastReceiver, and TileService subclasses (already in manifest but belt+suspenders)
-keep class com.voicedrop.service.VoiceDropService { *; }
-keep class com.voicedrop.service.TalkTileService { *; }
-keep class com.voicedrop.service.NotificationActionReceiver { *; }
-keep class com.voicedrop.service.AutoDeleteWorker { *; }

# Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory { *; }
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler { *; }
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# Enum classes
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# Remove logging in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
}
