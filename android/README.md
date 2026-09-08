# MiaoSpeed Android

MiaoSpeed的安卓移植

## 功能覆盖

| 页面 | 子命令 | 覆盖参数 |
|---|---|---|
| 服务 | `server` | bind / token / path / allowip / whitelist / interface / connthread / tasklimit / speedlimit / pausesecond / mmdb / serverpublickey / serverprivatekey / clientca / pprof / mtls / nospeed / upload / ipv6 / demo / verbose + 附加参数 |
| 工具 | `misc` | maxmind-update-license / interface / verbose + 附加参数 |
| 脚本 | `script` | file / interface / verbose + 附加参数 |

- 数值与文本留空 = 不传该 flag（Go 端走默认值）；布尔开关仅 true 时传递。
- 「附加参数」按 shell 规则切词后原样追加，可覆盖未来版本新增的任何 flag。
- 文件类参数（mmdb/证书/脚本）可用输入框右侧按钮：SAF 导入（复制到应用私有
  目录 `imports/`）或浏览应用目录（`misc` 下载的 mmdb 也在其中）。
- 进程工作目录为应用私有 `filesDir`；stdout/stderr 实时采集到「日志」页，支持
  复制 / 导出 / 自动滚动，并自动保存最近 10 份会话日志（`logs/`）。

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
- UI 参数持久化于 SharedPreferences，重启后保留。
