package com.miaospeed.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.miaospeed.android.ConfigStore
import com.miaospeed.android.ServerParams
import com.miaospeed.android.displayCommand
import com.miaospeed.android.toArgs

/** server 子命令：全部 CLI 参数与之一一对应 */
@Composable
fun ServerScreen() {
    val p by ConfigStore.server.collectAsStateWithLifecycle()

    fun set(transform: ServerParams.() -> Unit) {
        ConfigStore.saveServer(p.copy().also(transform))
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = 4.dp),
    ) {
        SectionCard("网络", "server 子命令的网络相关参数") {
            LabeledTextField(
                "监听地址 (-bind)", p.bind, { set { bind = it } },
                placeholder = "0.0.0.0:8765",
                enabled = !p.reverseOnly,
                hint = if (p.reverseOnly) "已开启「仅反向连接」，该参数不会传给 miaospeed" else null,
            )
            LabeledTextField(
                "令牌 (-token)", p.token, { set { token = it } },
                placeholder = "与面板/客户端一致的签名令牌",
                hint = "用于请求签名，反向连接时还用于握手认证；填写后两端必须一致",
            )
            LabeledTextField(
                "反向连接端点 (-connect)", p.connect, { set { connect = it } },
                placeholder = "ws://面板地址:8766/",
                hint = "本机没有公网 IP 时使用：由 miaospeed 主动拨出到面板的反向监听端口。" +
                    "可填多个，用逗号或换行分隔；填写后必须同时配置 -token",
                singleLine = false,
                minLines = 3,
            )
            SwitchRow(
                "仅反向连接（不监听 -bind）",
                "开启后不传 -bind，只保留反向拨出；需先填写 -connect",
                p.reverseOnly,
            ) { set { reverseOnly = it } }
            LabeledTextField("WebSocket 路径 (-path)", p.path, { set { path = it } }, placeholder = "留空为 /（不安全）")
            LabeledTextField(
                "允许访问的 IP 段 (-allowip)", p.allowip, { set { allowip = it } },
                placeholder = "192.168.1.0/24,10.12.13.2",
            )
            LabeledTextField(
                "Bot ID 白名单 (-whitelist)", p.whitelist, { set { whitelist = it } },
                placeholder = "1111,2222,3333",
            )
            LabeledTextField(
                "出口网卡 (-interface)", p.interfaceName, { set { interfaceName = it } },
                placeholder = "如 wlan0 / rmnet_data0，留空自动",
            )
        }

        SectionCard("功能开关") {
            SwitchRow("内嵌证书 TLS (-mtls)", "使用 Miaoko 签名证书进行 TLS 校验", p.mtls) { set { mtls = it } }
            SwitchRow("拒绝测速请求 (-nospeed)", "关闭所有下载测速任务", p.nospeed) { set { nospeed = it } }
            SwitchRow("允许上传测速 (-upload)", "开启所有上传测速任务", p.upload) { set { upload = it } }
            SwitchRow("启用 IPv6 (-ipv6)", "允许 IPv6 测速出站", p.ipv6) { set { ipv6 = it } }
            SwitchRow("演示模式 (-demo)", "自动生成 token/路径并输出 miaospeed:// 链接", p.demo) { set { demo = it } }
            SwitchRow("详细日志 (-verbose)", "输出系统级调试日志", p.verbose) { set { verbose = it } }
        }

        SectionCard("性能与限速", "留空使用默认值") {
            LabeledTextField(
                "并发线程 (-connthread)", p.connthread, { set { connthread = it } },
                placeholder = "64（默认）",
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            LabeledTextField(
                "任务队列上限 (-tasklimit)", p.tasklimit, { set { tasklimit = it } },
                placeholder = "1000（默认）",
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            LabeledTextField(
                "测速限速 B/s (-speedlimit)", p.speedlimit, { set { speedlimit = it } },
                placeholder = "0（默认，不限速）",
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            LabeledTextField(
                "测速后暂停秒数 (-pausesecond)", p.pausesecond, { set { pausesecond = it } },
                placeholder = "0（默认）",
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
        }

        SectionCard("数据与证书", "文件可先导入到应用目录，再自动填入路径") {
            PathField(
                "MaxMind 数据库 (-mmdb)", p.mmdb, { set { mmdb = it } },
                placeholder = "多个路径用英文逗号分隔", allowMulti = true,
                hint = "加载本地 mmdb 用于 GeoIP 查询",
            )
            PathField(
                "服务端公钥 PEM (-serverpublickey)", p.serverpublickey, { set { serverpublickey = it } },
                placeholder = "覆盖内嵌 TLS 公钥",
            )
            PathField(
                "服务端私钥 PEM (-serverprivatekey)", p.serverprivatekey, { set { serverprivatekey = it } },
                placeholder = "覆盖内嵌 TLS 私钥",
            )
            PathField(
                "客户端 CA PEM (-clientca)", p.clientca, { set { clientca = it } },
                placeholder = "可选 mTLS：校验客户端证书（需开启 -mtls）",
            )
            LabeledTextField(
                "pprof 监听 (-pprof)", p.pprof, { set { pprof = it } },
                placeholder = "如 127.0.0.1:6060，留空关闭",
            )
        }

        SectionCard("附加参数", "任何未在上方列出的 flag 都可在此原样追加（含未来新增）") {
            LabeledTextField(
                "额外参数", p.extraArgs, { set { extraArgs = it } },
                placeholder = "例如 -newflag value", singleLine = false, minLines = 2,
            )
        }

        CommandPreviewCard("libmiaospeed.so ${displayCommand(p.toArgs())}")
    }
}
