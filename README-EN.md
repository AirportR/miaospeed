<div align="center">
    <h1> MiaoSpeed </h1>
    <p>🐱 High-performance proxy testing backend 🚀</p>
    <p>English&nbsp &nbsp <a href="https://github.com/AirportR/miaospeed/blob/master/README.md">简体中文</a></p>
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

## Introduction

⚠️ This branch is a fork, as the original repository is no longer maintained by its developer.

miaospeed is a performance testing tool for proxy servers, written in Go.

## Features

- Cross-platform support for mainstream operating systems...
- Proxy protocol implementation based on [Mihomo](https://github.com/MetaCubeX/Mihomo)
- Backend service uses websocket protocol for full-duplex communication, supporting simultaneous testing by multiple clients.
- Supports mainstream outbound proxies Shadowsocks, Vmess, VLESS, Trojan, Hysteria2, AnyTLS, etc.
- Rich testing parameter configuration, supporting custom request body, timeout, concurrency, etc.
- Custom javascript testing script support, supporting custom testing logic
- Reverse connection support: when the backend sits behind NAT without a public ip, it can dial OUT to clients that do have one, it can serve several endpoints at the same time, and a control connection can resize each pool on the fly.


## Basic Usage

### Management Script

The repository includes `miaospeed.sh` for interactive installation, configuration, startup, shutdown, log viewing, and uninstallation on Linux.

Most Linux distributions can start the interactive installer with the following command:

```shell
curl -fsSL https://raw.githubusercontent.com/AirportR/miaospeed/master/miaospeed.sh -o /tmp/miaospeed.sh && bash /tmp/miaospeed.sh
```

### Pre-compiled Binary

* Help information
```shell
./miaospeed 
```
* View version
```shell
./miaospeed -version
```
* View websocket service help
```shell
./miaospeed server -help
```
### Compilation

Since miaospeed was originally used in conjunction with the closed-source project **miaoko**, some certificates and scripts are not open source. You need to complete the following files to successfully compile:

1. `./utils/embeded/BUILDTOKEN.key`: This is the `build TOKEN`, which is used to sign the miaospeed **single test request** structure to prevent your client from using miaospeed in a non-standard way causing data authenticity disputes. You can define it freely, for example: `1111|2222|33333333`, different segments separated by `|`.
2. `./preconfigs/embeded/miaokoCA/miaoko.crt`: When `-mtls` is enabled, miaospeed will read the certificate here to let the client do TLS verification.
3. `./preconfigs/embeded/miaokoCA/miaoko.key`: Same as above, this is the private key. (For these two, you can sign a certificate with openssl yourself, but it cannot be used for miaoko.)
4. `./preconfigs/embeded/ca-certificates.crt`: The built-in root certificate set of miaospeed, preventing malicious users from modifying system certificates to fake TLS RTT. (For debian users, you can get this file at `/etc/ssl/certs/ca-certificates.crt` after installing the `ca-certificates` package)

The following are **optional** operations:

1. `./engine/embeded/predefined.js`: This file defines some common methods in `JavaScript` (streaming media) scripts, such as `get()`, `safeStringify()`, `safeParse()`, `println()`. The default file is provided by the repository, and you can also modify it yourself.
2. `./engine/embeded/default_geoip.js`: Default `geoip` script, which needs to provide a `handler()` entry function. The default IP script is provided, and you can also modify it yourself.
3. `./engine/embeded/default_ip.js`: Default `ip_resolve` script, which needs to provide an `ip_resolve_default()` entry function to obtain the entry and exit IP. The default geoip script is provided, and you can also modify it yourself.

After you have created the above files, you can run `go build .` to build `miaospeed`.

### TLS and Client Certificates

`-mtls` enables the server TLS certificate so clients can verify the server identity. To verify client certificates when clients present them, also pass `-clientca <path>` with the trusted client CA certificate. This mode is optional client certificate verification: a presented client certificate must chain to that CA, while clients without a certificate continue to connect through the existing logic.

### Reverse Connection

In the normal mode miaospeed listens on a port and waits for clients (panels) to connect. When the machine running miaospeed has **no public ip** while the client does, miaospeed can **dial out** to the client instead:

```shell
./miaospeed server -connect wss://panel.example.com/reverse -token YOUR_TOKEN
```

`-connect` can be repeated, or its urls separated by commas, so a single backend serves several endpoints at once:

```shell
./miaospeed server -connect wss://a.example.com/reverse -connect wss://b.example.com/reverse -token YOUR_TOKEN
./miaospeed server -connect wss://a.example.com/reverse,wss://b.example.com/reverse -token YOUR_TOKEN
```

### Pre-compiled Binary Instructions

The pre-compiled binaries in this repository are **compatible** with the original closed-source client Miaoko.
The build token used is:
```
MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN
```
The corresponding TLS certificate cannot be provided here due to closed-source reasons. If you want to compile miaospeed yourself for the closed-source client Miaoko, please extract the certificate from the original repository's pre-compiled binary through special means.
If compatibility is not required, you may safely ignore this note.

### Integration Method

If you want to integrate miaospeed in other services, please refer to the client implementations listed below. You can also refer to the following approach:

1. The essence of miaospeed integration is to send commands and pass information through the websocket (ws) channel. Generally, you only need to connect to ws, construct a request structure, sign the request, and receive the results.
2. Connect to ws, this step is simple and doesn't need elaboration. (If you forcibly disconnect the connection on the client side, the task will be automatically terminated)
3. Construct the request structure, reference: https://github.com/AirportR/miaospeed/blob/fd7abecc2d36a0f18b08f048f9a53b7c0a26bd9e/interfaces/api_request.go#L50
4. Signature, reference: https://github.com/AirportR/miaospeed/blob/df6202409e87c5d944ab756608fd31d35390b5c0/utils/challenge.go#L39 where two parameters need to be passed in. The first parameter is the `startup TOKEN` (that is, the content after -token when you start miaospeed), and the second is the structure `req` you constructed in the second step. To put it simply, the signature method is to convert the structure to a JSON String and then cumulatively perform SHA512 HASH with the `startup TOKEN` and `build TOKEN` slices respectively. Finally, write the signed string to `req.Challenge`.
5. After sending the signed request, you can receive the return value. The structure returned by the server is unified as https://github.com/AirportR/miaospeed/blob/fd7abecc2d36a0f18b08f048f9a53b7c0a26bd9e/interfaces/api_response.go#L28


## Main Client Implementations

Since most of miaospeed’s functionality resides in the server, clients need to be implemented separately. You can refer to the following client implementations:
* miaoko (closed-source) Project address: None
* koipy (initially open-source, later closed-source) [Project address](https://github.com/koipy-org/koipy) [Project documentation](https://koipy.gitbook.io/koipy)
* Waku (closed-source, commercial) [Documentation](https://scx.gitbook.io/)

If there are other client implementations in the future, feel free to contribute

## Copyright and License

**miaospeed** is open-sourced under the AGPLv3 license. You can modify, contribute, distribute, and even use **miaospeed** commercially according to the AGPLv3 license. But please remember that you must comply with all obligations under the AGPLv3 license to avoid unnecessary legal disputes.

### Credits

miaospeed uses the following open source projects:

- Dreamacro/clash [GPLv3]
- MetaCubeX/Clash.Meta [GPLv3]
- juju/ratelimit [LGPLv3]
- dop251/goja [MIT]
- json-iterator/go [MIT]
- pion/stun [MIT]
- go-yaml/yaml [MIT]
- gorilla/websocket [BSD]
- jpillora/ipfilter [MIT]

## Abstract Design

If you want to contribute to miaospeed, you can refer to the following abstract design of miaospeed:

- **Matrix**: Data matrix [interfaces/matrix.go]. This is the smallest granularity of data that users want to obtain. For example, if a user wants to understand the RTT delay of a node, they can request miaospeed to test `TEST_PING_RTT` [for example: service/matrices/httpping/matrix.go].
- **Macro**: Runtime macro task [interfaces/macro.go]. If users want to run data matrices in batches, they often do repetitive things. For example, `TEST_PING_RTT` and `TEST_PING_HTTP` are mostly doing the same things. If two _Matrix_ are run independently, it will waste a lot of resources. Therefore, we define _Macro_ as the smallest granularity execution unit. The _Macro_ completes a series of time-consuming operations in parallel, and then the _Matrix_ will parse the data obtained from the _Macro_ run to fill its own content.
- **Vendor**: Service provider [interfaces/vendor.go]. miaospeed itself is just a testing tool, **it has no proxy capabilities**. Therefore, _Vendor_ serves as an interface that provides connection capabilities to miaospeed.
