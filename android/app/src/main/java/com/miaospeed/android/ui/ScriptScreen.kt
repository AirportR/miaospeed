package com.miaospeed.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.miaospeed.android.ConfigStore
import com.miaospeed.android.ScriptParams
import com.miaospeed.android.displayCommand
import com.miaospeed.android.toArgs

/** script 子命令：临时脚本测试 */
@Composable
fun ScriptScreen() {
    val p by ConfigStore.script.collectAsStateWithLifecycle()

    fun set(transform: ScriptParams.() -> Unit) {
        ConfigStore.saveScript(p.copy().also(transform))
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = 4.dp),
    ) {
        SectionCard("脚本测试 (script)", "等价于 miaospeed script -file <path>，运行一次并在日志页输出 JSON 结果") {
            PathField(
                "脚本文件 (-file)", p.file, { set { file = it } },
                placeholder = "JS 脚本文件路径",
            )
        }

        SectionCard("公共参数", "所有子命令共享") {
            LabeledTextField(
                "出口网卡 (-interface)", p.interfaceName, { set { interfaceName = it } },
                placeholder = "如 wlan0，留空自动",
            )
            SwitchRow("详细日志 (-verbose)", checked = p.verbose, onCheckedChange = { set { verbose = it } })
        }

        SectionCard("附加参数", "任何未在上方列出的 flag 都可在此原样追加") {
            LabeledTextField(
                "额外参数", p.extraArgs, { set { extraArgs = it } },
                placeholder = "例如 -newflag value", singleLine = false, minLines = 2,
            )
        }

        CommandPreviewCard("libmiaospeed.so ${displayCommand(p.toArgs())}")
    }
}
