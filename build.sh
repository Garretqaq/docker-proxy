#!/bin/bash

# 版本号
VERSION="1.0.0"
# 程序名称
BINARY_NAME="docker-proxy"

# 创建构建目录
mkdir -p build

# 支持的平台列表
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
)

# 遍历平台列表进行编译
for PLATFORM in "${PLATFORMS[@]}"; do
    # 分割平台信息
    IFS="/" read -r -a array <<< "$PLATFORM"
    GOOS="${array[0]}"
    GOARCH="${array[1]}"
    
    # 设置输出文件名
    if [ "$GOOS" == "windows" ]; then
        OUTPUT_NAME="$BINARY_NAME-$VERSION-$GOOS-$GOARCH.exe"
    else
        OUTPUT_NAME="$BINARY_NAME-$VERSION-$GOOS-$GOARCH"
    fi

    # 编译
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "build/$OUTPUT_NAME" main.go

    # 如果不是Windows，添加可执行权限
    if [ "$GOOS" != "windows" ]; then
        chmod +x "build/$OUTPUT_NAME"
    fi

    # 创建压缩包
    if [ "$GOOS" == "windows" ]; then
        zip -j "build/$OUTPUT_NAME.zip" "build/$OUTPUT_NAME"
    else
        tar -czf "build/$OUTPUT_NAME.tar.gz" -C build "$OUTPUT_NAME"
    fi
done

echo "Build complete! Check the build directory for binaries." 