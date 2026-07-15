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

## 基本用法

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
