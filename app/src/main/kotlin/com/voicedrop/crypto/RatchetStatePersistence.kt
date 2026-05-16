package com.voicedrop.crypto

import com.voicedrop.storage.ContactEntity

/**
 * DR3 ↔ DR6 bridge: serialize / deserialize a [RatchetState] over a
 * [ContactEntity]'s ratchet columns, using DR2 wrap-and-MAC for every
 * secret-bearing column.
 *
 * Row identity for HMAC binding is the `contacts.id` UTF-8 bytes per DR2 §9.2.
 *
 * Public-only columns (`dhs_pub`, `dhr_pub`, `ns`, `nr`, `pn`) are stored
 * unwrapped — they appear in cleartext on the wire so wrapping them adds no
 * confidentiality, but their HMAC-free state means a DB-write attacker can
 * scramble them. That's caught downstream as structural corruption / AEAD
 * failure (see [dr14]).
 *
 * `rk_wrapped` is NOT NULL at the schema level; the pre-bootstrap sentinel is a
 * zero-length ByteArray ([ContactEntity.rk_wrapped] defaults to `ByteArray(0)`).
 * `loadRatchetState` treats an empty `rk_wrapped` as "no ratchet yet" and
 * throws — bootstrap must have written real state before any encrypt.
 */
object RatchetStatePersistence {

    private const val COL_DHS_PRIV = "contacts.dhs_priv_wrapped"
    private const val COL_RK = "contacts.rk_wrapped"
    private const val COL_CKS = "contacts.cks_wrapped"
    private const val COL_CKR = "contacts.ckr_wrapped"

    /** No ratchet state on this contact (pre-bootstrap row). Encrypt path must surface this. */
    class RatchetNotBootstrapped(contactId: String) :
        IllegalStateException("contact $contactId has no ratchet state (pre-bootstrap)")

    /** Crypto column shape was unexpectedly NULL where the schema requires both halves. */
    class RatchetStateCorrupt(contactId: String, what: String) :
        IllegalStateException("contact $contactId ratchet state corrupt: $what")

    fun loadRatchetState(contact: ContactEntity, wrapMac: WrapMac): RatchetState {
        if (contact.rk_wrapped.isEmpty()) throw RatchetNotBootstrapped(contact.id)
        if (contact.rk_hmac.isEmpty()) throw RatchetStateCorrupt(contact.id, "rk_hmac empty but rk_wrapped non-empty")
        val rowId = contact.id.toByteArray(Charsets.UTF_8)

        val rk = wrapMac.unwrapAndVerify(COL_RK, rowId, contact.rk_wrapped, contact.rk_hmac)

        val dhsPriv: ByteArray? = when {
            contact.dhs_priv_wrapped == null && contact.dhs_priv_hmac == null -> null
            contact.dhs_priv_wrapped != null && contact.dhs_priv_hmac != null ->
                wrapMac.unwrapAndVerify(COL_DHS_PRIV, rowId, contact.dhs_priv_wrapped, contact.dhs_priv_hmac)
            else -> throw RatchetStateCorrupt(contact.id, "dhs_priv wrapped/hmac mismatch")
        }

        val cks: ByteArray? = when {
            contact.cks_wrapped == null && contact.cks_hmac == null -> null
            contact.cks_wrapped != null && contact.cks_hmac != null ->
                wrapMac.unwrapAndVerify(COL_CKS, rowId, contact.cks_wrapped, contact.cks_hmac)
            else -> throw RatchetStateCorrupt(contact.id, "cks wrapped/hmac mismatch")
        }

        val ckr: ByteArray? = when {
            contact.ckr_wrapped == null && contact.ckr_hmac == null -> null
            contact.ckr_wrapped != null && contact.ckr_hmac != null ->
                wrapMac.unwrapAndVerify(COL_CKR, rowId, contact.ckr_wrapped, contact.ckr_hmac)
            else -> throw RatchetStateCorrupt(contact.id, "ckr wrapped/hmac mismatch")
        }

        return RatchetState(
            dhsPriv = dhsPriv,
            dhsPub = contact.dhs_pub?.copyOf(),
            dhrPub = contact.dhr_pub?.copyOf(),
            rk = rk,
            cks = cks,
            ckr = ckr,
            ns = contact.ns,
            nr = contact.nr,
            pn = contact.pn,
            r = contact.reset_epoch
        )
    }

    /**
     * Returns a new [ContactEntity] with ratchet columns updated to reflect [state].
     * Caller upserts it inside the active Room transaction. All other contact
     * columns (identity, reset_*, repair flags) are preserved unchanged via `copy`.
     */
    fun saveRatchetState(contact: ContactEntity, state: RatchetState, wrapMac: WrapMac): ContactEntity {
        val rowId = contact.id.toByteArray(Charsets.UTF_8)

        val (rkW, rkH) = wrapMac.wrapAndMac(COL_RK, rowId, state.rk)

        val (dhsPrivW, dhsPrivH) = state.dhsPriv?.let { wrapMac.wrapAndMac(COL_DHS_PRIV, rowId, it) }
            ?.let { it.first to it.second } ?: (null to null)

        val (cksW, cksH) = state.cks?.let { wrapMac.wrapAndMac(COL_CKS, rowId, it) }
            ?.let { it.first to it.second } ?: (null to null)

        val (ckrW, ckrH) = state.ckr?.let { wrapMac.wrapAndMac(COL_CKR, rowId, it) }
            ?.let { it.first to it.second } ?: (null to null)

        return contact.copy(
            dhs_priv_wrapped = dhsPrivW,
            dhs_priv_hmac = dhsPrivH,
            dhs_pub = state.dhsPub?.copyOf(),
            dhr_pub = state.dhrPub?.copyOf(),
            rk_wrapped = rkW,
            rk_hmac = rkH,
            cks_wrapped = cksW,
            cks_hmac = cksH,
            ckr_wrapped = ckrW,
            ckr_hmac = ckrH,
            ns = state.ns,
            nr = state.nr,
            pn = state.pn
        )
    }
}
