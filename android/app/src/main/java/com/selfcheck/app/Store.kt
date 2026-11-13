package com.selfcheck.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** 설정(아이디, 반복 여부)과 마지막 결과를 저장합니다. */
object Store {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("selfcheck", Context.MODE_PRIVATE)

    fun usernames(ctx: Context): List<String> =
        (prefs(ctx).getString("usernames", "") ?: "")
            .split(',', ' ', '\n').map { it.trim().removePrefix("@") }.filter { it.isNotEmpty() }.distinct()

    fun usernamesRaw(ctx: Context) = prefs(ctx).getString("usernames", "") ?: ""
    fun setUsernames(ctx: Context, v: String) = prefs(ctx).edit().putString("usernames", v).apply()

    fun repeat(ctx: Context) = prefs(ctx).getBoolean("repeat", false)
    fun setRepeat(ctx: Context, v: Boolean) = prefs(ctx).edit().putBoolean("repeat", v).apply()

    private fun resultFile(ctx: Context) = File(ctx.filesDir, "results.json")

    fun saveResults(ctx: Context, rows: List<SiteResult>) {
        val arr = JSONArray()
        rows.forEach { r ->
            arr.put(JSONObject().apply {
                put("username", r.username); put("site", r.site); put("url", r.url)
                put("status", r.status); put("http", r.http ?: JSONObject.NULL)
                put("note", r.note); put("avatar", r.avatar ?: JSONObject.NULL)
                put("face", r.faceScore ?: JSONObject.NULL)
            })
        }
        val obj = JSONObject().put("time", System.currentTimeMillis()).put("rows", arr)
        val tmp = File(ctx.filesDir, "results.json.tmp")
        tmp.writeText(obj.toString())
        tmp.renameTo(resultFile(ctx))
    }

    fun loadResults(ctx: Context): Pair<Long, List<SiteResult>>? {
        val f = resultFile(ctx)
        if (!f.exists()) return null
        return runCatching {
            val obj = JSONObject(f.readText())
            val arr = obj.getJSONArray("rows")
            obj.getLong("time") to (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                SiteResult(
                    o.getString("username"), o.getString("site"), o.getString("url"),
                    o.getString("status"), if (o.isNull("http")) null else o.getInt("http"),
                    o.getString("note"), if (o.isNull("avatar")) null else o.getString("avatar"),
                    if (o.isNull("face")) null else o.getDouble("face"),
                )
            }
        }.getOrNull()
    }
}
