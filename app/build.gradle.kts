plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.room)
    alias(libs.plugins.aboutlibraries)
}

android {
    namespace = "com.voicedrop"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.voicedrop"
        minSdk = 28
        targetSdk = 36
        versionCode = 79
        versionName = "1.4.0.5"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    room {
        schemaDirectory("$projectDir/schemas")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.constraintlayout)

    implementation(libs.tink.android)
    implementation(libs.kopus)
    implementation(libs.zxing.android.embedded)

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    implementation(libs.work.runtime.ktx)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.aboutlibraries)
    implementation(libs.markwon.core)
    implementation(libs.markwon.linkify)
    implementation(libs.markwon.ext.tables)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.room.testing)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.androidx.test.core)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.espresso.core)
    androidTestImplementation(libs.room.testing)
}

// Bundle the repo-root PRIVACY.md into assets so the in-app viewer
// (PrivacyPolicyActivity) stays in sync with the canonical document.
val copyPrivacyPolicy by tasks.registering(Copy::class) {
    from(rootProject.file("PRIVACY.md"))
    into(layout.projectDirectory.dir("src/main/assets"))
}

tasks.named("preBuild") {
    dependsOn(copyPrivacyPolicy)
}

// Full stack traces in CI so test failures show the assertion site, not just
// the top-level throw site. Default Gradle reporter elides everything between.
tasks.withType<Test>().configureEach {
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
        showStackTraces = true
        showCauses = true
    }
}

// DR19 §12.8 — ratchet-path lint. Belt-and-braces against two regressions
// the strict-commit-ordering ratchet pipeline cannot survive:
//   1. Room's `withTransaction` coroutine extension — releases the per-contact
//      mutex on suspension points inside the transaction, which breaks the
//      [dr7] strict-commit-ordering invariant. The ratchet pipeline must use
//      `db.runInTransaction(Callable {...})` exclusively.
//   2. Direct `Cipher.getInstance(...)` calls in Ratchet*.kt — every AEAD use
//      must funnel through `KeyManager.wrapAndMac` / `unwrapAndVerify` (or the
//      `ChaCha20Poly1305Aead` wrapper) so the (column, row) HMAC binding from
//      [dr2] is enforced.
// Comments are stripped before matching so the deliberate "we don't use
// withTransaction" explainer in RatchetEncryptAndSend.kt doesn't trip.
val ratchetLint by tasks.registering {
    val ratchetSources = fileTree("src/main/kotlin/com/voicedrop/crypto") {
        include("Ratchet*.kt")
    }
    inputs.files(ratchetSources)
    doLast {
        val violations = mutableListOf<String>()
        val lineCommentRe = Regex("""//.*$""")
        val blockCommentRe = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val withTxRe = Regex("""(\.withTransaction\s*[{(]|\bimport\s+androidx\.room\.withTransaction\b)""")
        val cipherRe = Regex("""\bCipher\.getInstance\b""")
        ratchetSources.forEach { file ->
            val stripped = blockCommentRe.replace(file.readText(), "")
            stripped.lineSequence().forEachIndexed { idx, raw ->
                val line = lineCommentRe.replace(raw, "")
                if (withTxRe.containsMatchIn(line)) {
                    violations.add("${file.name}:${idx + 1}: withTransaction is forbidden in Ratchet*.kt — use db.runInTransaction(Callable {...}) (DR19 §12.8 / dr7)")
                }
                if (cipherRe.containsMatchIn(line)) {
                    violations.add("${file.name}:${idx + 1}: direct Cipher.getInstance is forbidden in Ratchet*.kt — must go through KeyManager.wrapAndMac / ChaCha20Poly1305Aead (DR19 §12.8 / dr2)")
                }
            }
        }
        if (violations.isNotEmpty()) {
            throw GradleException(
                "Ratchet-path lint failed:\n  " + violations.joinToString("\n  ")
            )
        }
        logger.lifecycle("ratchetLint: ${ratchetSources.files.size} file(s) checked, no violations")
    }
}

tasks.named("check") {
    dependsOn(ratchetLint)
}
