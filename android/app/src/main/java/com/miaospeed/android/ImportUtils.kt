package com.miaospeed.android

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File

/** 通过 SAF 把用户选择的文件复制到应用私有目录 imports/ 下，返回绝对路径 */
object ImportUtils {

    fun importFile(ctx: Context, uri: Uri): String? {
        return try {
            val name = queryName(ctx, uri) ?: "import-${System.currentTimeMillis()}"
            val dir = File(ctx.filesDir, "imports").apply { mkdirs() }
            val dst = File(dir, name)
            val ok = ctx.contentResolver.openInputStream(uri)?.use { ins ->
                dst.outputStream().use { ins.copyTo(it) }
            } != null
            if (!ok) return null
            AppRuntime.append("[app] 已导入文件: ${dst.absolutePath} (${formatSize(dst.length())})")
            dst.absolutePath
        } catch (t: Throwable) {
            AppRuntime.append("[app] 导入失败: ${t.message}")
            null
        }
    }

    private fun queryName(ctx: Context, uri: Uri): String? =
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }

    fun formatSize(bytes: Long): String = when {
        bytes >= 1 shl 20 -> "%.1f MB".format(bytes / 1048576.0)
        bytes >= 1 shl 10 -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }
}
