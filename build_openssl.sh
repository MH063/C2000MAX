#!/bin/bash
set -e

# 设置工具链路径
TOOLCHAIN_DIR="/home/openwrt/openwrt-sdk-21.02.0-mediatek-mt7622_gcc-8.4.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-8.4.0_musl"
export PATH="$TOOLCHAIN_DIR/bin:$PATH"

# 设置交叉编译变量
CROSS=aarch64-openwrt-linux-musl-
CC=${CROSS}gcc
CXX=${CROSS}g++
AR=${CROSS}ar
RANLIB=${CROSS}ranlib

# 构建目录
BUILD_DIR="/tmp/openssl-arm64"
INSTALL_DIR="/tmp/openssl-install"
SOURCE_DIR="/mnt/d/软件开发/MAX/路由管家"

echo "=========================================="
echo " OpenSSL 3.0.0 交叉编译 (ARM64)"
echo "=========================================="
echo ""

# 验证编译器
echo "[1/6] 验证交叉编译器..."
if ! command -v ${CC} &> /dev/null; then
    echo "❌ 错误: 找不到 ${CC}"
    echo "工具链路径: $TOOLCHAIN_DIR/bin"
    ls -la "$TOOLCHAIN_DIR/bin" | head -10
    exit 1
fi
${CC} --version
echo "✅ 编译器就绪"
echo ""

# 清理并创建目录
echo "[2/6] 准备构建环境..."
rm -rf "$BUILD_DIR" "$INSTALL_DIR"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR"
cd "$BUILD_DIR"

# 解压源码
echo "[3/6] 解压 OpenSSL 3.0.0..."
tar xzf "$SOURCE_DIR/openssl-3.0.0.tar.gz"
cd openssl-3.0.0
echo "✅ 解压完成"
echo ""

# 配置 OpenSSL
echo "[4/6] 配置 OpenSSL..."
./Configure \
    linux-aarch64 \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR/ssl" \
    --cross-compile-prefix="$CROSS" \
    shared \
    no-async \
    no-dso \
    no-threads \
    no-zlib \
    -O2 \
    -fPIC

echo "✅ 配置完成"
echo ""

# 编译
echo "[5/6] 编译 OpenSSL (预计 5-15 分钟)..."
make -j$(nproc)
echo "✅ 编译完成"
echo ""

# 安装
echo "[6/6] 安装到 $INSTALL_DIR..."
make install_sw
echo "✅ 安装完成"
echo ""

# 显示结果
echo "=========================================="
echo " 编译结果"
echo "=========================================="
echo ""
echo "库文件:"
ls -lh "$INSTALL_DIR/lib/"*.so* 2>/dev/null || find "$INSTALL_DIR" -name '*.so*' -exec ls -lh {} \;

# 复制到项目目录
echo ""
echo "复制到项目目录..."
mkdir -p "$SOURCE_DIR/files/openssl-libs"
cp -av "$INSTALL_DIR/lib/libssl.so"* "$SOURCE_DIR/files/openssl-libs/" 2>/dev/null || true
cp -av "$INSTALL_DIR/lib/libcrypto.so"* "$SOURCE_DIR/files/openssl-libs/" 2>/dev/null || true

echo ""
echo "=========================================="
echo " ✅ 编译成功！"
echo "=========================================="
echo ""
echo "库文件位置: $SOURCE_DIR/files/openssl-libs/"
ls -lh "$SOURCE_DIR/files/openssl-libs/"
