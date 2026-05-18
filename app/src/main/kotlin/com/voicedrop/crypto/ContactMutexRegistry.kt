package com.voicedrop.crypto

import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-wide registry of per-contact ratchet mutexes. Same `Mutex` instance is
 * shared across encrypt ([dr7]), decrypt ([dr8]), and outbox replay ([dr11]) so
 * that load-modify-write on a contact's ratchet state is serialized end-to-end.
 *
 * **Load-bearing for correctness** — see [00-overview.md §4](../../../../../../../plan/08-dr/00-overview.md).
 * Without serialization two concurrent encrypts can both derive `mk` for the
 * same `n`, AEAD-seal under the same key with the zero nonce, and produce
 * catastrophic ChaCha20-Poly1305 key-and-nonce reuse.
 *
 * Single-process invariant is enforced by [ManifestInvariantTest] (no
 * `android:process=`). If a multi-process configuration is ever introduced this
 * registry stops being sound — DR7 §8.3 documents the SQLite `BEGIN IMMEDIATE`
 * + version-column fallback.
 */
object ContactMutexRegistry {

    private val mutexes = ConcurrentHashMap<String, Mutex>()

    fun forContact(contactId: String): Mutex =
        mutexes.computeIfAbsent(contactId) { Mutex() }

    /** Test-only: drop a contact's mutex so a fresh one is created on next access. */
    internal fun clear() {
        mutexes.clear()
    }
}
