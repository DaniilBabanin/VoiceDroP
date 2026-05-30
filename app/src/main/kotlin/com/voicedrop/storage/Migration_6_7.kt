package com.voicedrop.storage

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Finding #2 (Phase B) — additive schema for outbox idempotency. No data migration.
 *
 *   - pending_outbound_frames.acked_uuid: nullable BLOB; the acked DATA UUID on
 *     RECEIPT rows, used by B1's "RECEIPT already pending?" existence query.
 *   - index on (contact_id, acked_uuid) backs that query and the per-contact
 *     RECEIPT count.
 *   - messages.receipt_resends: NOT NULL DEFAULT 0; per-message re-emit counter
 *     bounding the patient-replay Ns drip.
 *
 * Index name MUST match Room's generated name `index_<table>_<col1>_<col2>` so
 * Room's schema validation at open time accepts the migrated DB.
 */
val Migration_6_7 = object : Migration(6, 7) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE pending_outbound_frames ADD COLUMN acked_uuid BLOB")
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_pending_outbound_frames_contact_id_acked_uuid " +
                "ON pending_outbound_frames (contact_id, acked_uuid)"
        )
        db.execSQL("ALTER TABLE messages ADD COLUMN receipt_resends INTEGER NOT NULL DEFAULT 0")
    }
}
