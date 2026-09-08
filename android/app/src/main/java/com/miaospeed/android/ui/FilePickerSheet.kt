package com.miaospeed.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.miaospeed.android.ImportUtils

/** 列出应用私有目录中的文件供选择（misc 下载的 mmdb、导入的文件都在这里） */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilePickerSheet(onDismiss: () -> Unit, onPick: (String) -> Unit) {
    val ctx = LocalContext.current
    val files = remember {
        ctx.filesDir.walkTopDown().filter { it.isFile }.sortedBy { it.path }.toList()
    }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(bottom = 24.dp)) {
            Text(
                "选择应用目录中的文件",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
            )
            Text(
                "进程工作目录即此目录：misc 下载的 mmdb、导入的证书/脚本都保存在这里。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
            )
            if (files.isEmpty()) {
                Text(
                    "（目录为空，可先用输入框右侧的导入按钮把文件复制进来）",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp),
                )
            } else {
                LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(files) { f ->
                        ListItem(
                            headlineContent = { Text(f.name) },
                            supportingContent = {
                                Text(
                                    "${f.relativeToOrNull(ctx.filesDir)?.path ?: f.path}  ·  " +
                                        ImportUtils.formatSize(f.length()),
                                )
                            },
                            modifier = Modifier.clickable { onPick(f.absolutePath) },
                        )
                    }
                }
            }
        }
    }
}
