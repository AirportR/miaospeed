package com.miaospeed.android

import org.json.JSONObject

/**
 * 与 miaospeed 命令行一一对应的参数模型。
 *
 * 规则：
 * - 字符串为空 → 不传该 flag（让 Go 端走默认值）
 * - 布尔为 false → 不传；true → 传开关本身
 * - extraArgs 会被切词后原样追加到末尾，覆盖未来新增的任何 flag
 */

data class ServerParams(
    var bind: String = "0.0.0.0:8765",
    var token: String = "",
    var path: String = "",
    var allowip: String = "0.0.0.0/0,::/0",
    var whitelist: String = "",
    var interfaceName: String = "",
    var mtls: Boolean = false,
    var nospeed: Boolean = false,
    var upload: Boolean = false,
    var ipv6: Boolean = false,
    var demo: Boolean = false,
    var verbose: Boolean = false,
    var connthread: String = "",
    var tasklimit: String = "",
    var speedlimit: String = "",
    var pausesecond: String = "",
    var mmdb: String = "",
    var serverpublickey: String = "",
    var serverprivatekey: String = "",
    var clientca: String = "",
    var pprof: String = "",
    var extraArgs: String = "",
)

fun ServerParams.toArgs(): List<String> = buildList {
    add("server")
    addOpt("bind", bind)
    addOpt("token", token)
    addOpt("path", path)
    addOpt("allowip", allowip)
    addOpt("whitelist", whitelist)
    addOpt("interface", interfaceName)
    addOpt("connthread", connthread)
    addOpt("tasklimit", tasklimit)
    addOpt("speedlimit", speedlimit)
    addOpt("pausesecond", pausesecond)
    addOpt("mmdb", mmdb)
    addOpt("serverpublickey", serverpublickey)
    addOpt("serverprivatekey", serverprivatekey)
    addOpt("clientca", clientca)
    addOpt("pprof", pprof)
    addFlag("mtls", mtls)
    addFlag("nospeed", nospeed)
    addFlag("upload", upload)
    addFlag("ipv6", ipv6)
    addFlag("demo", demo)
    addFlag("verbose", verbose)
    addAll(tokenize(extraArgs))
}

fun ServerParams.toJson(): JSONObject = JSONObject().apply {
    put("bind", bind); put("token", token); put("path", path); put("allowip", allowip)
    put("whitelist", whitelist); put("interfaceName", interfaceName)
    put("mtls", mtls); put("nospeed", nospeed); put("upload", upload); put("ipv6", ipv6)
    put("demo", demo); put("verbose", verbose)
    put("connthread", connthread); put("tasklimit", tasklimit)
    put("speedlimit", speedlimit); put("pausesecond", pausesecond)
    put("mmdb", mmdb); put("serverpublickey", serverpublickey); put("serverprivatekey", serverprivatekey)
    put("clientca", clientca); put("pprof", pprof); put("extraArgs", extraArgs)
}

fun serverParamsFromJson(j: JSONObject?): ServerParams = ServerParams(
    bind = j?.optString("bind")?.takeIf { it.isNotBlank() } ?: "0.0.0.0:8765",
    token = j?.optString("token") ?: "",
    path = j?.optString("path") ?: "",
    allowip = j?.optString("allowip")?.takeIf { it.isNotBlank() } ?: "0.0.0.0/0,::/0",
    whitelist = j?.optString("whitelist") ?: "",
    interfaceName = j?.optString("interfaceName") ?: "",
    mtls = j?.optBoolean("mtls", false) ?: false,
    nospeed = j?.optBoolean("nospeed", false) ?: false,
    upload = j?.optBoolean("upload", false) ?: false,
    ipv6 = j?.optBoolean("ipv6", false) ?: false,
    demo = j?.optBoolean("demo", false) ?: false,
    verbose = j?.optBoolean("verbose", false) ?: false,
    connthread = j?.optString("connthread") ?: "",
    tasklimit = j?.optString("tasklimit") ?: "",
    speedlimit = j?.optString("speedlimit") ?: "",
    pausesecond = j?.optString("pausesecond") ?: "",
    mmdb = j?.optString("mmdb") ?: "",
    serverpublickey = j?.optString("serverpublickey") ?: "",
    serverprivatekey = j?.optString("serverprivatekey") ?: "",
    clientca = j?.optString("clientca") ?: "",
    pprof = j?.optString("pprof") ?: "",
    extraArgs = j?.optString("extraArgs") ?: "",
)

data class MiscParams(
    var license: String = "",
    var interfaceName: String = "",
    var verbose: Boolean = false,
    var extraArgs: String = "",
)

fun MiscParams.toArgs(): List<String> = buildList {
    add("misc")
    addOpt("maxmind-update-license", license)
    addOpt("interface", interfaceName)
    addFlag("verbose", verbose)
    addAll(tokenize(extraArgs))
}

fun MiscParams.toJson(): JSONObject = JSONObject().apply {
    put("license", license); put("interfaceName", interfaceName)
    put("verbose", verbose); put("extraArgs", extraArgs)
}

fun miscParamsFromJson(j: JSONObject?): MiscParams = MiscParams(
    license = j?.optString("license") ?: "",
    interfaceName = j?.optString("interfaceName") ?: "",
    verbose = j?.optBoolean("verbose", false) ?: false,
    extraArgs = j?.optString("extraArgs") ?: "",
)

data class ScriptParams(
    var file: String = "",
    var interfaceName: String = "",
    var verbose: Boolean = false,
    var extraArgs: String = "",
)

fun ScriptParams.toArgs(): List<String> = buildList {
    add("script")
    addOpt("file", file)
    addOpt("interface", interfaceName)
    addFlag("verbose", verbose)
    addAll(tokenize(extraArgs))
}

fun ScriptParams.toJson(): JSONObject = JSONObject().apply {
    put("file", file); put("interfaceName", interfaceName)
    put("verbose", verbose); put("extraArgs", extraArgs)
}

fun scriptParamsFromJson(j: JSONObject?): ScriptParams = ScriptParams(
    file = j?.optString("file") ?: "",
    interfaceName = j?.optString("interfaceName") ?: "",
    verbose = j?.optBoolean("verbose", false) ?: false,
    extraArgs = j?.optString("extraArgs") ?: "",
)

private fun MutableList<String>.addOpt(name: String, value: String) {
    val v = value.trim()
    if (v.isNotEmpty()) {
        add("-$name")
        add(v)
    }
}

private fun MutableList<String>.addFlag(name: String, value: Boolean) {
    if (value) add("-$name")
}

/** 简易 shell 切词：支持单/双引号包裹含空白的参数 */
fun tokenize(text: String): List<String> {
    val out = ArrayList<String>()
    val sb = StringBuilder()
    var quote: Char? = null
    for (c in text) {
        when {
            quote != null -> if (c == quote) quote = null else sb.append(c)
            c == '"' || c == '\'' -> quote = c
            c.isWhitespace() -> {
                if (sb.isNotEmpty()) {
                    out.add(sb.toString())
                    sb.clear()
                }
            }
            else -> sb.append(c)
        }
    }
    if (sb.isNotEmpty()) out.add(sb.toString())
    return out
}

/** 用于日志预览的命令行拼接 */
fun displayCommand(args: List<String>): String =
    args.joinToString(" ") { a -> if (a.any { it.isWhitespace() }) "\"$a\"" else a }
