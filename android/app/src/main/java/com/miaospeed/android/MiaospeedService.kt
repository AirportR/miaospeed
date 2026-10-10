package com.miaospeed.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * 前台服务：以子进程方式运行 nativeLibraryDir/libmiaospeed.so，
 * stdout/stderr 合并采集进 AppRuntime 日志。
 */
class MiaospeedService : Service() {

    companion object {
        const val ACTION_START = "com.miaospeed.android.action.START"
        const val ACTION_STOP = "com.miaospeed.android.action.STOP"
        const val EXTRA_ARGS = "args"
        private const val CHANNEL_ID = "miaospeed_run"
        private const val NOTIF_ID = 9527
    }

    @Volatile
    private var process: Process? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProcess()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val args = intent.getStringArrayListExtra(EXTRA_ARGS).orEmpty()
                if (AppRuntime.procState.value is ProcState.Running) {
                    AppRuntime.append("[app] 已有实例在运行，请先停止")
                    return START_NOT_STICKY
                }
                startFg(args.firstOrNull() ?: "server")
                startProcess(args)
            }
        }
        return START_NOT_STICKY
    }

    private fun startFg(title: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "后台运行", NotificationManager.IMPORTANCE_LOW).apply {
                description = "MiaoSpeed 后台运行状态"
                setShowBadge(false)
            }
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, MiaospeedService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this, 2,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_speed)
            .setContentTitle("MiaoSpeed 正在运行")
            .setContentText("子命令: $title")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(Notification.Action.Builder(null, "停止", stopIntent).build())
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun startProcess(args: List<String>) {
        val bin = File(applicationInfo.nativeLibraryDir, "libmiaospeed.so")
        if (!bin.exists()) {
            AppRuntime.append("[app] 错误: 未找到可执行文件 ${bin.absolutePath}（请确认安装的是 arm64-v8a 版本）")
            AppRuntime.procState.value = ProcState.Finished(args.firstOrNull() ?: "server", -1)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val title = args.firstOrNull() ?: "server"
        AppRuntime.procState.value = ProcState.Running(title)
        AppRuntime.append("[app] ===== 启动 =====")
        AppRuntime.append("[app] \$ libmiaospeed.so ${args.joinToString(" ")}")
        AppRuntime.append("[app] 工作目录: ${filesDir.absolutePath}")
        AppRuntime.newSessionLog()

        wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "miaospeed:run")
            .also { it.acquire() }

        thread(name = "miaospeed-proc") {
            var code = -1
            try {
                val p = ProcessBuilder(listOf(bin.absolutePath) + args)
                    .directory(filesDir)
                    .redirectErrorStream(true)
                    .start()
                process = p
                BufferedReader(InputStreamReader(p.inputStream, Charsets.UTF_8)).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        AppRuntime.append(line)
                    }
                }
                code = p.waitFor()
                AppRuntime.append("[app] 进程已退出，退出码: $code")
            } catch (t: Throwable) {
                AppRuntime.append("[app] 运行异常: ${t.message}")
            } finally {
                AppRuntime.procState.value = ProcState.Finished(title, code)
                AppRuntime.append("[app] ===== 结束 =====")
                AppRuntime.closeSessionLog()
                wakeLock?.takeIf { it.isHeld }?.release()
                wakeLock = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun stopProcess() {
        val p = process
        if (p == null || !p.isAlive) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        AppRuntime.append("[app] 正在停止（发送 SIGTERM）…")
        runCatching { p.destroy() }
        thread(name = "miaospeed-kill") {
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                AppRuntime.append("[app] 5 秒未退出，强制结束")
                runCatching { p.destroyForcibly() }
            }
        }
    }

    override fun onDestroy() {
        val p = process
        if (p != null && p.isAlive) {
            runCatching { p.destroy() }
            thread(name = "miaospeed-kill") {
                if (!p.waitFor(3, TimeUnit.SECONDS)) {
                    runCatching { p.destroyForcibly() }
                }
            }
        }
        wakeLock?.takeIf { it.isHeld }?.release()
        super.onDestroy()
    }
}
