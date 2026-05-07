#!/bin/bash
# OpenSSL 3.0.0 交叉编译脚本 - 为 ARM64 (aarch64_cortex-a53) 架构编译
# 适用于 OpenWrt 路由器

set -e

echo "=========================================="
echo " OpenSSL 3.0.0 交叉编译脚本 (ARM64)"
echo "=========================================="
echo ""

# 设置变量
SOURCE_DIR="/mnt/d/软件开发/MAX/路由管家"
BUILD_DIR="/tmp/openssl-arm64-build"
INSTALL_DIR="/tmp/openssl-arm64-install"
OPENSSL_TAR="$SOURCE_DIR/openssl-3.0.0.tar.gz"

# 检查源文件是否存在
if [ ! -f "$OPENSSL_TAR" ]; then
    echo "❌ 错误: 找不到 $OPENSSL_TAR"
    exit 1
fi

echo "✅ 找到 OpenSSL 源码包: $OPENSSL_TAR"
echo ""

# 清理并创建构建目录
echo "[1/7] 准备构建环境..."
rm -rf "$BUILD_DIR" "$INSTALL_DIR"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# 解压源码
echo "[2/7] 解压 OpenSSL 源码..."
cd "$BUILD_DIR"
tar xzf "$OPENSSL_TAR"
echo "✅ 解压完成"
ls -la
echo ""

# 检查交叉编译工具链
echo "[3/7] 检查交叉编译工具链..."
if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "⚠️ 未找到 aarch64-linux-gnu-gcc"
    echo ""
    echo "请执行以下命令安装交叉编译工具链："
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu"
    echo ""
    echo "安装完成后，重新运行此脚本"
    exit 1
fi

CROSS_COMPILE="aarch64-linux-gnu-"
CC="${CROSS_COMPILE}gcc"
CXX="${CROSS_COMPILE}g++"
AR="${CROSS_COMPILE}ar"
RANLIB="${CROSS_COMPILE}ranlib"

echo "✅ 找到交叉编译工具链:"
echo "   CC:      $CC"
echo "   CXX:     $CXX"
echo "   AR:      $AR"
echo "   RANLIB:  $RANLIB"
$CC --version | head -1
echo ""

# 配置 OpenSSL
echo "[4/7] 配置 OpenSSL..."
cd openssl-3.0.0

./Configure \
    linux-aarch64 \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR/ssl" \
    --cross-compile-prefix="$CROSS_COMPILE" \
    no-async \
    no-dso \
    no-shared \
    no-threads \
    no-zlib \
    -DOPENSSL_NO_SECURE_MEMORY \
    -O2 \
    -fPIC

echo "✅ 配置完成"
echo ""

# 编译
echo "[5/7] 编译 OpenSSL (这可能需要 10-20 分钟)..."
make -j$(nproc)
echo "✅ 编译完成"
echo ""

# 安装
echo "[6/7] 安装到 $INSTALL_DIR..."
make install
echo "✅ 安装完成"
echo ""

# 提取共享库
echo "[7/7] 提取共享库文件..."
cd "$BUILD_DIR"

# 重新编译为共享库
cd openssl-3.0.0
make clean

./Configure \
    linux-aarch64 \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR/ssl" \
    --cross-compile-prefix="$CROSS_COMPILE" \
    shared \
    no-async \
    no-dso \
    no-threads \
    no-zlib \
    -DOPENSSL_NO_SECURE_MEMORY \
    -O2 \
    -fPIC

make -j$(nproc)
make install

# 查找生成的库文件
echo ""
echo "=========================================="
echo " 编译结果"
echo "=========================================="
find "$INSTALL_DIR" -name 'libssl.so*' -o -name 'libcrypto.so*' | while read lib; do
    echo "  $lib"
    ls -lh "$lib"
done

# 复制到源目录
echo ""
echo "复制库文件到项目目录..."
mkdir -p "$SOURCE_DIR/files/openssl-libs"
cp -av "$INSTALL_DIR"/lib/libssl.so* "$SOURCE_DIR/files/openssl-libs/"
cp -av "$INSTALL_DIR"/lib/libcrypto.so* "$SOURCE_DIR/files/openssl-libs/"

echo ""
echo "=========================================="
echo " ✅ 编译完成！"
echo "=========================================="
echo ""
echo "库文件位置: $SOURCE_DIR/files/openssl-libs/"
ls -lh "$SOURCE_DIR/files/openssl-libs/"
echo ""
echo "下一步："
echo "1. 将这些库文件上传到路由器的 /usr/lib/ 目录"
echo "2. 重新测试 stubby 服务"
