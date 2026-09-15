package com.miaospeed.android.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.miaospeed.android.AppRuntime
import com.miaospeed.android.ConfigStore
import com.miaospeed.android.MiaospeedService
import com.miaospeed.android.ProcState
import com.miaospeed.android.hasFlagValue
import com.miaospeed.android.lastFlagValue
import com.miaospeed.android.toArgs

enum class MainTab(val label: String, val icon: ImageVector) {
    SERVER("服务", Icons.Filled.Speed),
    MISC("工具", Icons.Filled.Build),
    SCRIPT("脚本", Icons.Filled.Code),
    LOG("日志", Icons.Filled.Terminal),
    ABOUT("关于", Icons.Filled.Info),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MiaospeedApp() {
    val ctx = LocalContext.current
    var tab by rememberSaveable { mutableStateOf(MainTab.SERVER) }
    val procState by AppRuntime.procState.collectAsStateWithLifecycle()
    val running = procState is ProcState.Running

    val notifPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    fun startNow() {
        if (running) return
        val args = when (tab) {
            MainTab.SERVER -> {
                val s = ConfigStore.server.value
                val a = s.toArgs()
                if (s.reverseOnly && !a.hasFlagValue("connect")) {
                    Toast.makeText(ctx, "已开启「仅反向连接」，请先填写 -connect 端点", Toast.LENGTH_SHORT).show()
                    return
                }
                if (a.hasFlagValue("connect") && a.lastFlagValue("token").isNullOrBlank()) {
                    Toast.makeText(ctx, "-connect 需要 -token（也可写在「附加参数」里）", Toast.LENGTH_SHORT).show()
                    return
                }
                a
            }
            MainTab.MISC -> ConfigStore.misc.value.toArgs()
            MainTab.SCRIPT -> {
                val s = ConfigStore.script.value
                if (s.file.isBlank()) {
                    Toast.makeText(ctx, "请先填写或导入脚本文件 (-file)", Toast.LENGTH_SHORT).show()
                    return
                }
                s.toArgs()
            }
            MainTab.LOG, MainTab.ABOUT -> return
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        ContextCompat.startForegroundService(
            ctx,
            Intent(ctx, MiaospeedService::class.java)
                .setAction(MiaospeedService.ACTION_START)
                .putStringArrayListExtra(MiaospeedService.EXTRA_ARGS, ArrayList<String>(args)),
        )
        tab = MainTab.LOG
    }

    fun stopNow() {
        ctx.startService(
            Intent(ctx, MiaospeedService::class.java).setAction(MiaospeedService.ACTION_STOP),
        )
    }

    Scaffold(
        modifier = Modifier.imePadding(),
        topBar = {
            TopAppBar(
                title = { Text("MiaoSpeed") },
                actions = {
                    val (text, color) = when (val st = procState) {
                        is ProcState.Running -> "运行中" to MaterialTheme.colorScheme.primary
                        is ProcState.Finished -> "退出码 ${st.exitCode}" to MaterialTheme.colorScheme.error
                        ProcState.Idle -> "未运行" to MaterialTheme.colorScheme.outline
                    }
                    Row(
                        Modifier.padding(end = 16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(Modifier.size(8.dp).background(color, CircleShape))
                        Spacer(Modifier.width(6.dp))
                        Text(text, style = MaterialTheme.typography.labelLarge)
                    }
                },
            )
        },
        bottomBar = {
            Column {
                if (tab != MainTab.LOG && tab != MainTab.ABOUT) {
                    ActionBar(
                        running = running,
                        startLabel = "启动 " + when (tab) {
                            MainTab.SERVER -> "server"
                            MainTab.MISC -> "misc"
                            else -> "script"
                        },
                        onStart = { startNow() },
                        onStop = { stopNow() },
                    )
                }
                NavigationBar {
                    MainTab.entries.forEach { t ->
                        NavigationBarItem(
                            selected = tab == t,
                            onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = t.label) },
                            label = { Text(t.label) },
                        )
                    }
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (tab) {
                MainTab.SERVER -> ServerScreen()
                MainTab.MISC -> MiscScreen()
                MainTab.SCRIPT -> ScriptScreen()
                MainTab.LOG -> LogScreen()
                MainTab.ABOUT -> AboutScreen()
            }
        }
    }
}

@Composable
private fun ActionBar(
    running: Boolean,
    startLabel: String,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = onStart, enabled = !running, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text(startLabel)
            }
            OutlinedButton(onClick = onStop, enabled = running, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Stop, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("停止")
            }
        }
    }
}
