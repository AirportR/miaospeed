# MiaoSpeed Android

MiaoSpeed的安卓移植

## 功能覆盖

| 页面 | 子命令 | 覆盖参数 |
|---|---|---|
| 服务 | `server` | bind / token / path / connect / allowip / whitelist / interface / connthread / tasklimit / speedlimit / pausesecond / mmdb / serverpublickey / serverprivatekey / clientca / pprof / mtls / nospeed / upload / ipv6 / demo / verbose + 附加参数 |
| 工具 | `misc` | maxmind-update-license / interface / verbose + 附加参数 |
| 脚本 | `script` | file / interface / verbose + 附加参数 |

- 数值与文本留空 = 不传该 flag（Go 端走默认值）；布尔开关仅 true 时传递。
- 「附加参数」按 shell 规则切词后原样追加，可覆盖未来版本新增的任何 flag。
  注意 Go 的 flag 包遇到第一个不以 `-` 开头的裸词就会停止解析，别在这里写裸词。
- 文件类参数（mmdb/证书/脚本）可用输入框右侧按钮：SAF 导入（复制到应用私有
  目录 `imports/`）或浏览应用目录（`misc` 下载的 mmdb 也在其中）。
- 进程工作目录为应用私有 `filesDir`；stdout/stderr 实时采集到「日志」页，支持
  复制 / 导出 / 自动滚动，并自动保存最近 10 份会话日志（`logs/`）。

## 反向连接（-connect）

本机没有公网 IP 时，可以让 miaospeed 主动拨出到面板的反向监听端口：

- 「反向连接端点 (-connect)」支持多端点，用**逗号或换行**分隔。每个端点会展开成
  一对 `-connect <url>`，Go 端为每个端点建独立连接池与独立重连退避。
- 端点形如 `ws://<面板IP>:8766/` 或 `wss://...`，路径任意（koipy 侧路由为
  `/{tail:.*}`）。端口对应面板配置里的 `reverseListen`。
- 填了 `-connect` 就必须同时填 `-token`，否则 Go 端启动即报错退出。
- 开「仅反向连接」后不传 `-bind`，进入纯反向模式（只拨出、不监听）。
  该开关打开时 `-bind` 输入框会置灰。
- 客户端只按逗号切分，**不认换行与空格**，所以换行是在 App 侧切好后逐条传下去的。
  实测漏过去的后果：换行会让 `url.Parse` 报 `invalid control character in URL`（启动即
  exit 1，看得见）；空格更麻烦——被编码成 `%20` 混进路径后**能通过校验**，只注册 1 个
  端点、永远连不上却无明显报错。

## 构建

前置：JDK 17、Android SDK（platforms;android-35、build-tools）、Go ≥ 1.25。

```bash
# 1. 编译 android/arm64 二进制（或用仓库根 Makefile: make android-so）
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath \
  -ldflags '-w -s -buildid=' \
  -o android/app/src/main/jniLibs/arm64-v8a/libmiaospeed.so .

# 2. 构建 APK（在 android/ 目录）
./gradlew assembleRelease

# 一键（仓库根目录）
make android
```

**Gradle 缓存固定在项目内**：`gradlew` / `gradlew.bat` 在未显式设置 `GRADLE_USER_HOME`
时会把它指到 `android/.gradle`，因此依赖缓存与 Gradle 发行版都落在本目录下，
不再写入全局的 `~/.gradle`。`android/.gitignore` 已排除 `.gradle/`，不会入库。
若确实要用别的位置，显式设 `GRADLE_USER_HOME` 即可覆盖（注意 Git Bash 下要传
Windows 风格路径，脚本不会对显式传入的值做 `cygpath` 转换）。

**不保留常驻构建进程**：`gradle.properties` 里设了 `org.gradle.daemon=false` 与
`kotlin.compiler.execution.strategy=in-process`。前者让 Gradle 用完即退，后者避免
Kotlin 编译另外拉起一个常驻 daemon（那一个不受 `org.gradle.daemon` 控制）。
代价是每次构建都要冷启动，增量构建约 2-3 分钟（开启 daemon 时约 1 分钟）。
若想换回常驻以加快连续构建，删掉这两行，并在收尾时手动执行 `./gradlew --stop`
释放内存。

产物：`android/app/build/outputs/apk/release/miaospeed-<核心版本>-<abi>.apk`，

Release 签名使用 `android/keystore.jks`（自签）。签名信息（路径/alias/密码）从同目录
的 `keystore.properties` 读取，该文件与 keystore 本体均不入库；缺失时回退 debug 签名。
首次生成示例（注意 PKCS12 格式下 keyPassword 必须与 storePassword 一致）：

```bash
keytool -genkeypair -v -keystore android/keystore.jks -alias miaospeed-release \
  -keyalg RSA -keysize 4096 -validity 36500 \
  -storepass <your_storepass> -keypass <same_as_storepass> \
  -dname "CN=MiaoSpeed Release, OU=miaospeed, O=miaospeed, C=CN"
```

随后把 `storeFile` / `storePassword` / `keyAlias` / `keyPassword` 写入
`android/keystore.properties`（该文件已被 .gitignore 排除，不会提交）。

`local.properties` 指向本机 SDK，例如：`sdk.dir=D:/path/to/Android/Sdk`（不要提交）。

## 运行机制

- **前台服务**：类型 `dataSync`，通知栏提供「停止」按钮；持 PARTIAL_WAKE_LOCK，
  息屏不影响长时间测速。
- **进程停止**：向子进程发 SIGTERM（miaospeed 优雅退出），5 秒未退出会强行停止。
- **输入法**：内容区与底部操作栏随键盘整体上抬（`Modifier.imePadding()` 加在
  `Scaffold` 上），输入框获焦后会自动滚动到键盘之上，不再被输入法遮挡。
- UI 参数持久化于 SharedPreferences，重启后保留。
