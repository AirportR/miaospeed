package com.miaospeed.android

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.BufferedWriter
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

sealed interface ProcState {
    data object Idle : ProcState
    data class Running(val title: String) : ProcState
    data class Finished(val title: String, val exitCode: Int) : ProcState
}

/** 进程状态 + 内存环形日志 + 会话日志文件 */
object AppRuntime {

    private const val MAX_LINES = 4000

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log
    private val buf = ArrayList<String>(1024)

    val procState = MutableStateFlow<ProcState>(ProcState.Idle)

    private var appCtx: Context? = null
    private var sessionWriter: BufferedWriter? = null
    private val ioLock = Any()

    fun init(ctx: Context) {
        appCtx = ctx.applicationContext
    }

    fun append(line: String) {
        synchronized(buf) {
            if (buf.size >= MAX_LINES) buf.removeAt(0)
            buf.add(line)
            _log.value = ArrayList(buf)
        }
        synchronized(ioLock) {
            runCatching {
                sessionWriter?.write(line)
                sessionWriter?.newLine()
            }
        }
    }

    fun clearLog() {
        synchronized(buf) {
            buf.clear()
            _log.value = emptyList()
        }
    }

    /** 每次启动进程时开启新的会话日志文件，最多保留 10 份 */
    fun newSessionLog() {
        synchronized(ioLock) {
            closeSessionLogLocked()
            val ctx = appCtx ?: return
            val dir = File(ctx.filesDir, "logs").apply { mkdirs() }
            dir.listFiles()?.sortedByDescending { it.name }?.drop(9)?.forEach { it.delete() }
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
            sessionWriter = File(dir, "session-$stamp.log").bufferedWriter()
        }
    }

    fun closeSessionLog() {
        synchronized(ioLock) { closeSessionLogLocked() }
    }

    private fun closeSessionLogLocked() {
        runCatching {
            sessionWriter?.flush()
            sessionWriter?.close()
        }
        sessionWriter = null
    }
}
