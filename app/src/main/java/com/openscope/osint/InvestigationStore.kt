package com.openscope.osint

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject

data class InvestigationEntry(
    val id: Long,
    val createdAt: Long,
    val result: AnalysisResult
)

class InvestigationStore(context: Context) : SQLiteOpenHelper(context, "openscope_cases.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                subject TEXT NOT NULL,
                module TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """.trimIndent())
        db.execSQL("CREATE INDEX idx_investigations_created ON investigations(created_at DESC)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun save(result: AnalysisResult): Long {
        val payload = JSONObject().apply {
            put("summary", result.summary)
            put("explanation", result.explanation)
            put("findings", JSONArray().apply {
                result.findings.forEach { finding ->
                    put(JSONObject().apply {
                        put("title", finding.title)
                        put("value", finding.value)
                        put("detail", finding.detail)
                        put("level", finding.level)
                    })
                }
            })
        }
        val values = android.content.ContentValues().apply {
            put("created_at", System.currentTimeMillis())
            put("subject", result.subject)
            put("module", result.module)
            put("payload", payload.toString())
        }
        return writableDatabase.insert("investigations", null, values)
    }

    fun list(limit: Int = 100): List<InvestigationEntry> {
        val output = mutableListOf<InvestigationEntry>()
        readableDatabase.query(
            "investigations",
            arrayOf("id", "created_at", "subject", "module", "payload"),
            null, null, null, null, "created_at DESC", limit.coerceIn(1, 500).toString()
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val payload = runCatching { JSONObject(cursor.getString(4)) }.getOrNull() ?: continue
                val findingsJson = payload.optJSONArray("findings") ?: JSONArray()
                val findings = (0 until findingsJson.length()).mapNotNull { index ->
                    val item = findingsJson.optJSONObject(index) ?: return@mapNotNull null
                    Finding(
                        item.optString("title"),
                        item.optString("value"),
                        item.optString("detail"),
                        item.optString("level", "info")
                    )
                }
                val subject = cursor.getString(2)
                val module = cursor.getString(3)
                output += InvestigationEntry(
                    cursor.getLong(0),
                    cursor.getLong(1),
                    AnalysisResult(
                        subject, module, payload.optString("summary"), findings,
                        payload.optString("explanation")
                    )
                )
            }
        }
        return output
    }

    fun delete(id: Long): Int = writableDatabase.delete("investigations", "id=?", arrayOf(id.toString()))
    fun clearAll(): Int = writableDatabase.delete("investigations", null, null)
}
