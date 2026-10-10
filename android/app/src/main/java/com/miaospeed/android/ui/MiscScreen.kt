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
import com.miaospeed.android.MiscParams
import com.miaospeed.android.displayCommand
import com.miaospeed.android.toArgs

/** misc 子命令：MaxMind 数据库更新 */
@Composable
fun MiscScreen() {
    val p by ConfigStore.misc.collectAsStateWithLifecycle()

    fun set(transform: MiscParams.() -> Unit) {
        ConfigStore.saveMisc(p.copy().also(transform))
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = 4.dp),
    ) {
        SectionCard("MaxMind 数据库更新 (misc)", "等价于 miaospeed misc -maxmind-update-license") {
            LabeledTextField(
                "License Key (-maxmind-update-license)", p.license, { set { license = it } },
                placeholder = "maxmind.com 账号的 license key",
                hint = "将下载 GeoLite2-ASN / GeoLite2-City 到应用目录（覆盖同名文件），之后可在服务页 -mmdb 中引用",
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
