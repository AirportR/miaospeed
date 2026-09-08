package com.miaospeed.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.miaospeed.android.AppRuntime
import com.miaospeed.android.ProcState

@Composable
fun LogScreen() {
    val lines by AppRuntime.log.collectAsStateWithLifecycle()
    val procState by AppRuntime.procState.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val listState = rememberLazyListState()
    var autoScroll by rememberSaveable { mutableStateOf(true) }
    var confirmClear by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            runCatching {
                ctx.contentResolver.openOutputStream(uri)?.use { os ->
                    os.write(lines.joinToString("\n").toByteArray(Charsets.UTF_8))
                }
            }.onSuccess { Toast.makeText(ctx, "日志已导出", Toast.LENGTH_SHORT).show() }
                .onFailure { Toast.makeText(ctx, "导出失败: ${it.message}", Toast.LENGTH_SHORT).show() }
        }
    }

    LaunchedEffect(lines.size) {
        if (autoScroll && lines.isNotEmpty()) listState.animateScrollToItem(lines.size - 1)
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val (text, color) = when (val st = procState) {
                is ProcState.Running -> "运行中" to MaterialTheme.colorScheme.primary
                is ProcState.Finished -> "已退出（${st.exitCode}）" to MaterialTheme.colorScheme.error
                ProcState.Idle -> "未运行" to MaterialTheme.colorScheme.outline
            }
            Box(Modifier.size(8.dp).background(color, CircleShape))
            Spacer(Modifier.width(6.dp))
            Text(text, style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.weight(1f))
            FilterChip(
                selected = autoScroll,
                onClick = { autoScroll = !autoScroll },
                label = { Text("滚动") },
            )
            IconButton(onClick = {
                val cm = ctx.getSystemService(ClipboardManager::class.java)
                cm?.setPrimaryClip(ClipData.newPlainText("log", lines.joinToString("\n")))
                Toast.makeText(ctx, "已复制 ${lines.size} 行", Toast.LENGTH_SHORT).show()
            }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "复制日志")
            }
            IconButton(onClick = { exportLauncher.launch("miaospeed-log.txt") }) {
                Icon(Icons.Filled.Save, contentDescription = "导出日志")
            }
            IconButton(onClick = { confirmClear = true }) {
                Icon(Icons.Filled.Delete, contentDescription = "清空日志")
            }
        }
        HorizontalDivider()

        if (lines.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "暂无日志\n启动后输出将在此显示",
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
            ) {
                items(lines.size) { i ->
                    Text(
                        lines[i],
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                        modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp),
                    )
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("清空日志") },
            text = { Text("仅清空界面显示的日志，不影响已导出或会话日志文件。") },
            confirmButton = {
                TextButton(onClick = {
                    AppRuntime.clearLog()
                    confirmClear = false
                }) { Text("清空") }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("取消") }
            },
        )
    }
}
