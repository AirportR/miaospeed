<div align="center">
    <h1> MiaoSpeed - 喵速 </h1>
    <p>🐱 高性能代理测速后端 🚀</p>
    <p><a href="https://github.com/AirportR/miaospeed/blob/master/README-EN.md">English</a> &nbsp;&nbsp; 简体中文</p>
    <a href="https://koipy.gitbook.io/koipy/doc/miaospeed-hou-duan"><img src="https://img.shields.io/static/v1?message=doc&color=blue&logo=go&label=miaospeed"></a> 
    <img src="https://img.shields.io/github/license/AirportR/miaospeed">
    <a href="https://github.com/AirportR/miaospeed/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
    <br>
    <img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/airportr/miaospeed">
    <img alt="Docker Image Size" src="https://img.shields.io/docker/image-size/airportr/miaospeed">
    <br>
    <a href="https://github.com/AirportR/miaospeed/"><img src="https://img.shields.io/github/stars/AirportR/miaospeed?style=social"></a>
	<br>
	<br>
</div>

---

## 简介

⚠️ 本分支为 fork，原仓库作者已不再维护。

miaospeed 是一个使用 Go 编写的代理服务器性能测试解决方案。

## 特性

- 跨平台支持，兼容主流操作系统（Windows、Linux、MacOS）。
- 基于 [Mihomo](https://github.com/MetaCubeX/Mihomo) 的代理协议实现。
- 后端服务使用 WebSocket 协议进行全双工通信，支持多个客户端同时测试。
- 支持主流出站代理协议：Shadowsocks、Vmess、VLESS、Trojan、Hysteria2、AnyTLS 等。
- 丰富的测试参数配置，支持自定义请求体、超时、并发数等。
- 支持自定义 JavaScript 测试脚本，可实现自定义测试逻辑。
- 支持反向连接：后端位于 NAT 后没有公网时，可主动外连到有公网的客户端。

## 基本用法

### 管理脚本

仓库提供了 `miaospeed.sh`，用于在Linux上交互式安装、配置、启动、停止、查看日志和卸载 miaospeed。

大部分Linux 发行版可使用以下命令一键启动交互式安装：

```shell
curl -fsSL https://raw.githubusercontent.com/AirportR/miaospeed/master/miaospeed.sh -o /tmp/miaospeed.sh && bash /tmp/miaospeed.sh
```

### 预编译二进制

* 查看帮助信息
```shell
./miaospeed 
```
* 查看版本
```
./miaospeed -version
```
* 查看 websocket 服务用法
```
./miaospeed server -help
```


### 编译

由于 miaospeed 最初与闭源项目 miaoko 搭配使用，因此部分证书与脚本未开源。您需要补齐以下文件以成功编译:

1. `./utils/embeded/BUILDTOKEN.key`: 这是 `编译TOKEN`，用于给 miaospeed 的 单次测试请求 结构体签名，避免客户端以非标准方式使用 miaospeed 导致数据真实性争议。您可以随便定义它，例如: `1111|2222|33333333`，不同段用 `|` 切开。
2. `./preconfigs/embeded/miaokoCA/miaoko.crt`: 当 `-mtls` 启用时，miaospeed 会读取这里的证书让客户端做 TLS 验证。
3. `./preconfigs/embeded/miaokoCA/miaoko.key`: 同上，这是私钥。(对于这两个您可以自己用 openssl 签一个证书，但它不能用于 miaoko。)
4. `./preconfigs/embeded/ca-certificates.crt`: miaospeed 自带的根证书集，防止有恶意用户修改系统更证书以作假 TLS RTT。（对于 debian 用户，您可以在安装 `ca-certificates` 包后，在 `/etc/ssl/certs/ca-certificates.crt` 获取这个文件）

以下为可选文件：

1. `./engine/embeded/predefined.js`: 这个文件定义了 `JavaScript` (流媒体)脚本中一些通用方法，例如 `get()`, `safeStringify()`, `safeParse()`, `println()`，默认文件已提供，您也可以自行修改。
2. `./engine/embeded/default_geoip.js`: 默认的 `geoip` 脚本，需要提供一个 `handler()` 入口函数。默认ip脚本已提供，您也可以自行修改。
3. `./engine/embeded/default_ip.js`: 默认的 `ip_resolve` 脚本，需要提供一个 `ip_resolve_default()` 入口函数，用于获取入口、出口的 IP。默认geoip脚本已提供，您也可以自行修改。

当您新建好以上文件后，就可以运行 `go build .` 构建 `miaospeed` 了。

### TLS 与客户端证书

`-mtls` 会启用服务端 TLS 证书，供客户端验证服务端身份。若需要在客户端提供证书时验证客户端证书，可同时传入 `-clientca <path>` 指定服务端信任的客户端 CA 证书。此模式为可选客户端证书校验：客户端提供证书时必须能被该 CA 验证；客户端不提供证书时仍按原逻辑继续连接。

### 反向连接（Reverse Connect）

正常模式下 miaospeed 作为服务端监听端口，等待客户端（面板）主动连接。当 miaospeed 所在机器**没有公网**而客户端有公网时，可以让 miaospeed **主动外连**客户端：

```shell
./miaospeed server -connect wss://panel.example.com/reverse -token YOUR_TOKEN
```

- `-connect` 可与 `-bind` 同时使用（本地监听与反连并行）；只给 `-connect` 时不开启本地监听。
- 除 `-token` 外，其余服务端参数（`-connthread`、`-speedlimit`、`-nospeed` 等）在反连模式下同样生效。
- 反连固定维持 **4 条**活跃出站连接（连接池），每条连接都是独立完整的测试会话；断开后按 1s~60s 指数退避自动重连。
- 出站连接带 ping/pong 心跳（默认 30s，可被客户端在 ack 中覆盖），防止 NAT 空闲断链；`wss` 使用系统根证书校验。

**客户端（面板）侧需要实现的握手契约**（`reverse-v1`）：

1. 面板提供一个 WebSocket 端点接收 miaospeed 的外连。连接建立后，miaospeed 会发送第一条 JSON 消息 `ReverseHello`（字段名与现有协议一致，均为 PascalCase）：

| 字段 | 说明 |
| --- | --- |
| `Type` | 固定为 `"hello"` |
| `Protocol` | 协议版本，当前为 `"reverse-v1"` |
| `Version` | miaospeed 版本号 |
| `Nonce` | 随机字符串 |
| `Timestamp` | Unix 秒级时间戳 |
| `Sign` | `hashMiaoSpeed(token, "reverse-hello\|" + Nonce + "\|" + Timestamp)` |

2. 面板用同一 `token` 校验 `Sign`（算法与请求签名一致，见 `utils/challenge.go`），然后回 `ReverseAck`：

| 字段 | 说明 |
| --- | --- |
| `Type` | `"ack"` 表示接受；其他值为拒绝，miaospeed 会断开并退避重试 |
| `Protocol` | 原样返回 `reverse-v1`，版本协商锚点 |
| `Sign` | `hashMiaoSpeed(token, hello.Sign)`，证明面板持有同一 token（双向认证） |
| `Version` / `Name` | 面板版本与名称，仅用于日志 |
| `Timestamp` | 面板时间戳，用于时钟偏差排查 |
| `SessionID` | 面板为该连接分配的会话 ID，用于日志关联 |
| `Heartbeat` | 心跳间隔（秒），`0` 表示使用后端默认 30s |
| `MaxTasks` | 建议的单连接最大并发任务数，`0` 表示不限制（后端仅记录） |
| `Error` | 拒绝原因，`Type != "ack"` 时使用 |

3. 握手完成后，该连接按原生 miaospeed 协议收发（面板发送签名 `SlaveRequest`，后端流式返回 `SlaveResponse`），与主动连接模式完全一致。注意面板侧需要响应后端的 ping（标准 WebSocket 库默认行为）。

**对接面板的两个实现前提**：

- **TLS 证书**：反连出站使用 Go 系统根证书做 TLS 校验，因此面板的 `wss://` 端点必须使用受信 CA 签发的证书；后端生态默认的 Miaoko 自签证书体系（`-mtls`）并不用于反连。若面板使用自签证书，后端会在 TLS 校验阶段直接失败。
- **BUILDTOKEN 耦合**：反连握手签名与正常请求签名共用同一个 `hashMiaoSpeed` 原语，而后端编译时会把自己嵌入的 `BUILDTOKEN` 混入摘要。面板侧签名/校验实现必须与后端保持一致（即复用与官方请求签名相同的那套实现、嵌入相同的 BUILDTOKEN）；仅算法相同但 BUILDTOKEN 不同的构建会校验失败。

完整实现可参考 `tests/reverse_test.go` 中的 mock panel。

### 预编译二进制说明

仓库提供的预编译二进制文件与闭源客户端 **Miaoko 兼容**。
所使用的 build token 为：
```
MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN
```

由于Miaoko闭源，对应的 TLS 证书无法提供。如果您需要自行编译一个可与 Miaoko 兼容的版本，请通过特殊方式从原仓库的预编译二进制中提取证书。
若不需要兼容，可忽略本说明。
### 对接方法

如果您想在其他服务内对接 miaospeed，可以参考如下思路:

1. miaospeed 对接本质是通过 ws 通道发送指令、传递信息。一般来说，您只需要连接 ws，构建请求结构体，签名请求，接收结果即可。
2. 连接 ws，这一步很简单，也就不用赘述了。（如果您在客户端强制断开链接，则任务会被自动中止）
3. 构建请求结构体，参考: https://github.com/AirportR/miaospeed/blob/fd7abecc2d36a0f18b08f048f9a53b7c0a26bd9e/interfaces/api_request.go#L50
4. 签名，参考: https://github.com/AirportR/miaospeed/blob/df6202409e87c5d944ab756608fd31d35390b5c0/utils/challenge.go#L39 其中需要传入两个参数。第一个参数是 `启动TOKEN` （即您启动 miaospeed 时传入的 -token 后的内容），第二个就是在第二步中您构建的结构体 `req`。签名的方法，通俗一些说明就是将结构体转换为 JSON String 然后与 `启动TOKEN` 和 `编译TOKEN` 切片分别累积做 SHA512 HASH。最后，将签名的字符串写入 `req.Challenge` 即可。
5. 发送完成签名后的请求，您就可以接收返回值了。服务器返回的结构体统一为 https://github.com/AirportR/miaospeed/blob/fd7abecc2d36a0f18b08f048f9a53b7c0a26bd9e/interfaces/api_response.go#L28


## 主要客户端实现
由于 miaospeed 的大部分功能体现为后端服务，因此需要自行实现客户端。可参考以下实现：
* miaoko (闭源) 项目地址：无
* koipy (初版开源，后续闭源) [项目地址](https://github.com/koipy-org/koipy) [项目文档](https://koipy.gitbook.io/koipy)

如未来有其他客户端实现，欢迎贡献。
## 版权与协议

miaospeed 采用 AGPLv3 协议开源，您可以按照 AGPLv3 协议对 miaospeed 进行修改、贡献、分发、乃至商用。但请切记，您必须遵守 AGPLv3 协议下的一切义务，以免发生不必要的法律纠纷。

### 主要开源依赖公示

miaospeed 采用了如下的开源项目:

- Dreamacro/clash [GPLv3]
- MetaCubeX/Clash.Meta [GPLv3]
- juju/ratelimit [LGPLv3]
- dop251/goja [MIT]
- json-iterator/go [MIT]
- pion/stun [MIT]
- go-yaml/yaml [MIT]
- gorilla/websocket [BSD]
- jpillora/ipfilter [MIT]

## 抽象设计

如果您想贡献 miaospeed，您可以参考以下 miaospeed 的抽象设计:

- **Matrix**: 数据矩阵 [interfaces/matrix.go]。即用户想要获取的某个数据的最小颗粒度。例如，用户希望了解某个节点的 RTT 延迟，则 TA 可以要求 miaospeed 对 `TEST_PING_RTT` [例如: service/matrices/httpping/matrix.go] 进行测试。
- **Macro**: 运行时宏任务 [interfaces/macro.go]。如果用户希望批量运行数据矩阵，他们往往会做重复的事情。例如 `TEST_PING_RTT` 与 `TEST_PING_HTTP` 大多数时间都在做相同的事情。如果将两个 _Matrix_ 独立运行，则会浪费大量资源。因此，我们定义了 _Macro_ 最为一个最小颗粒度的执行体。由 _Macro_ 并行完成一系列耗时的操作，随后，_Matrix_ 将解析 _Macro_ 运行得到的数据，以填充自己的内容。
- **Vendor**: 服务提供商 [interfaces/vendor.go]。miaospeed 本身只是一个测试工具，**它不具备任何代理能力**。因此，_Vendor_ 作为一个接口，为 miaospeed 提供了链接能力。
