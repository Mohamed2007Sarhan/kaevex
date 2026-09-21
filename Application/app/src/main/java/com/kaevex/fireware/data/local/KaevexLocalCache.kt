package com.kaevex.fireware.data.local

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.kaevex.fireware.data.model.AlertItem
import com.kaevex.fireware.data.model.ServerNode
import com.kaevex.fireware.data.supabase.MobileActivityLog

class KaevexLocalCache(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "kaevex_soc.db"
        private const val DATABASE_VERSION = 2

        private const val TABLE_ALERTS = "alerts"
        private const val TABLE_SERVERS = "servers"
        private const val TABLE_TELEMETRY = "telemetry_cache"
        private const val TABLE_MOBILE_LOGS = "mobile_logs"
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE $TABLE_ALERTS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                severity TEXT,
                source TEXT,
                message TEXT,
                timestamp_ms INTEGER
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE $TABLE_SERVERS (
                id INTEGER PRIMARY KEY,
                name TEXT,
                ip TEXT,
                port INTEGER,
                role TEXT,
                status TEXT,
                ping_ms INTEGER,
                threats INTEGER,
                is_locked INTEGER,
                token TEXT
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE $TABLE_TELEMETRY (
                cache_key TEXT PRIMARY KEY,
                json_payload TEXT,
                updated_at INTEGER
            )
            """.trimIndent()
        )

        db.execSQL(
            """
            CREATE TABLE $TABLE_MOBILE_LOGS (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                title TEXT,
                details TEXT,
                device_info TEXT,
                user_email TEXT,
                timestamp_ms INTEGER,
                is_synced INTEGER DEFAULT 0
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_ALERTS")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_SERVERS")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_TELEMETRY")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_MOBILE_LOGS")
        onCreate(db)
    }

    // --- Alert History Operations ---
    fun insertAlert(alert: AlertItem) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("time", alert.time)
            put("severity", alert.severity)
            put("source", alert.source)
            put("message", alert.message)
            put("timestamp_ms", System.currentTimeMillis())
        }
        db.insert(TABLE_ALERTS, null, values)
    }

    fun insertAlerts(alerts: List<AlertItem>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (alert in alerts) {
                val values = ContentValues().apply {
                    put("time", alert.time)
                    put("severity", alert.severity)
                    put("source", alert.source)
                    put("message", alert.message)
                    put("timestamp_ms", System.currentTimeMillis())
                }
                db.insert(TABLE_ALERTS, null, values)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun getRecentAlerts(limit: Int = 50): List<AlertItem> {
        val list = mutableListOf<AlertItem>()
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT id, time, severity, source, message FROM $TABLE_ALERTS ORDER BY id DESC LIMIT ?",
            arrayOf(limit.toString())
        )
        cursor.use {
            while (it.moveToNext()) {
                list.add(
                    AlertItem(
                        id = it.getInt(0),
                        time = it.getString(1),
                        severity = it.getString(2),
                        source = it.getString(3),
                        message = it.getString(4)
                    )
                )
            }
        }
        return list
    }

    fun clearAlerts() {
        writableDatabase.delete(TABLE_ALERTS, null, null)
    }

    // --- Telemetry Cache Operations ---
    fun putCache(key: String, json: String) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("cache_key", key)
            put("json_payload", json)
            put("updated_at", System.currentTimeMillis())
        }
        db.insertWithOnConflict(TABLE_TELEMETRY, null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun getCache(key: String): String? {
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT json_payload FROM $TABLE_TELEMETRY WHERE cache_key = ?",
            arrayOf(key)
        )
        cursor.use {
            if (it.moveToFirst()) {
                return it.getString(0)
            }
        }
        return null
    }

    // --- Mobile Telemetry & Activity Log Operations ---
    fun insertMobileLog(
        eventType: String,
        title: String,
        details: String,
        deviceInfo: String,
        userEmail: String?,
        isSynced: Boolean = false
    ): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("event_type", eventType)
            put("title", title)
            put("details", details)
            put("device_info", deviceInfo)
            put("user_email", userEmail)
            put("timestamp_ms", System.currentTimeMillis())
            put("is_synced", if (isSynced) 1 else 0)
        }
        return db.insert(TABLE_MOBILE_LOGS, null, values)
    }

    fun getRecentMobileLogs(limit: Int = 50): List<MobileActivityLog> {
        val list = mutableListOf<MobileActivityLog>()
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT id, event_type, title, details, device_info, user_email FROM $TABLE_MOBILE_LOGS ORDER BY id DESC LIMIT ?",
            arrayOf(limit.toString())
        )
        cursor.use {
            while (it.moveToNext()) {
                list.add(
                    MobileActivityLog(
                        id = it.getLong(0),
                        eventType = it.getString(1) ?: "EVENT",
                        title = it.getString(2) ?: "",
                        details = it.getString(3) ?: "",
                        deviceInfo = it.getString(4) ?: "",
                        userEmail = it.getString(5)
                    )
                )
            }
        }
        return list
    }

    fun markMobileLogSynced(id: Long) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("is_synced", 1)
        }
        db.update(TABLE_MOBILE_LOGS, values, "id = ?", arrayOf(id.toString()))
    }

    fun clearMobileLogs() {
        writableDatabase.delete(TABLE_MOBILE_LOGS, null, null)
    }
}
