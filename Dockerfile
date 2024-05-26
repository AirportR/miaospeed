# 使用 Golang 的 Alpine 版本作为构建阶段
FROM golang:alpine3.19 AS builder

# 接受构建时传入的参数
ARG MS_BUILDTOKEN
ENV BUILDTOKEN=$MS_BUILDTOKEN

# 复制当前目录下的所有文件到 /opt
COPY . /opt

# 设置工作目录
WORKDIR /opt

# 安装必要的包，生成证书，并进行构建
RUN apk add --no-cache \
    ca-certificates openssl && \
    echo $BUILDTOKEN >> /opt/utils/embeded/BUILDTOKEN.key && \
    mkdir -p /opt/preconfigs/embeded/miaokoCA && \
    openssl req -x509 -newkey ec:<(openssl ecparam -name secp256r1) -nodes -keyout /opt/preconfigs/embeded/miaokoCA/miaoko.key -out /opt/preconfigs/embeded/miaokoCA/miaoko.crt -subj "/CN=fulltclash.com" && \
    go build .

# 使用更小的 Alpine 镜像作为运行阶段
FROM alpine:latest

# 设置工作目录
WORKDIR /opt

# 从构建阶段复制生成的可执行文件到运行阶段的镜像中
COPY --from=builder /opt/miaospeed /opt/miaospeed

# 设置容器启动时的入口点
ENTRYPOINT ["/opt/miaospeed"]
