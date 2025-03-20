# 使用多阶段构建
# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /data/app

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o docker-proxy main.go

# 第二阶段：运行阶段
FROM alpine:latest

# 安装CA证书
RUN apk --no-cache add ca-certificates

# 设置工作目录
WORKDIR /data/app

# 从构建阶段复制二进制文件
COPY --from=builder /data/app/docker-proxy .

# 暴露端口
EXPOSE 9000

# 设置容器启动命令
CMD ["./docker-proxy"] 