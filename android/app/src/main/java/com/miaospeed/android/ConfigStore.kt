package com.miaospeed.android

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject

/** UI 参数的持久化与全局状态 */
object ConfigStore {

    private lateinit var prefs: SharedPreferences

    val server = MutableStateFlow(ServerParams())
    val misc = MutableStateFlow(MiscParams())
    val script = MutableStateFlow(ScriptParams())

    fun init(ctx: Context) {
        prefs = ctx.getSharedPreferences("miaospeed_ui", Context.MODE_PRIVATE)
        server.value = serverParamsFromJson(parse(prefs.getString("server", null)))
        misc.value = miscParamsFromJson(parse(prefs.getString("misc", null)))
        script.value = scriptParamsFromJson(parse(prefs.getString("script", null)))
    }

    private fun parse(raw: String?): JSONObject? =
        raw?.let { runCatching { JSONObject(it) }.getOrNull() }

    fun saveServer(p: ServerParams) {
        server.value = p
        prefs.edit().putString("server", p.toJson().toString()).apply()
    }

    fun saveMisc(p: MiscParams) {
        misc.value = p
        prefs.edit().putString("misc", p.toJson().toString()).apply()
    }

    fun saveScript(p: ScriptParams) {
        script.value = p
        prefs.edit().putString("script", p.toJson().toString()).apply()
    }
}
