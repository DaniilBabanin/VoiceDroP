package com.voicedrop.storage

/**
 * Finding #2 (Phase B) — bounds for `pending_outbound_frames` RECEIPT growth.
 * Mirrors [SkippedKeyMaintenance]'s role for the skipped-key table.
 */
object OutboxMaintenance {

    /**
     * Per-contact cap on pending RECEIPT rows. Mirrors the skipped-key cap scale;
     * RECEIPTs are ~sub-KB wrapped, so 2000 ≈ sub-MB worst case per contact and
     * comfortably exceeds any legitimate offline catch-up flush. Refusing past
     * this (never evicting) is safe because RECEIPTs are recoverable; DATA/RESET
     * rows are never touched.
     */
    const val OUTBOX_RECEIPT_CAP_PER_CONTACT: Int = 2000

    /**
     * Per-message cap on RECEIPT *re-emits* (after the original). Bounds the
     * patient-replay Ns drip to ≤ K advances per distinct captured DATA frame.
     * K=5 comfortably covers any realistic RECEIPT loss/recovery.
     */
    const val RECEIPT_RESEND_CAP: Int = 5
}
