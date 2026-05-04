#!/bin/bash

set -e

PROJECT_DIR="/mnt/d/软件开发/MAX/路由管家"
TOOLCHAIN="/opt/aarch64-linux-musl-cross"
PACKAGES_DIR="$PROJECT_DIR/files/packages"
BUILD_DIR="/tmp/libcares_build"

echo "========================================="
echo "  libcares 1.34.6 交叉编译脚本"
echo "  使用 aarch64-musl 工具链"
echo "========================================="

export PATH="$TOOLCHAIN/bin:$PATH"
export CC=aarch64-linux-musl-gcc
export CXX=aarch64-linux-musl-g++
export AR=aarch64-linux-musl-ar
export RANLIB=aarch64-linux-musl-ranlib
export STRIP=aarch64-linux-musl-strip
export HOST=aarch64-linux-musl
export CROSS_COMPILE=aarch64-linux-musl-

echo "[1/7] 清理旧的构建目录..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[2/7] 解压源码包..."
tar xzf "$PROJECT_DIR/c-ares-1.34.6.tar.gz"
cd c-ares-1.34.6

echo "[3/7] 运行autoreconf..."
if [ -f "buildconf" ]; then
    ./buildconf
elif [ -f "configure.ac" ] || [ -f "configure.in" ]; then
    autoreconf -fi
fi

echo "[4/7] 配置编译选项..."
./configure \
    --host=$HOST \
    --prefix=/usr \
    --enable-shared \
    --enable-static \
    --disable-tests \
    --disable-examples-docs \
    --without-random \
    --disable-debug \
    CFLAGS="-O2 -pipe -fPIC" \
    LDFLAGS="-Wl,--gc-sections"

echo "[5/7] 编译..."
make -j$(nproc)

echo "[6/7] 安装到临时目录..."
make install DESTDIR="$BUILD_DIR/install"

echo "[7/7] 打包IPK..."
IPK_NAME="libcares_1.34.6-1_aarch64_cortex-a53.ipk"
IPK_DIR="$BUILD_DIR/ipk"

mkdir -p "$IPK_DIR"/{CONTROL,data/usr/lib}

cp "$BUILD_DIR/install/usr/lib/libcares.so"* "$IPK_DIR/data/usr/lib/"
$STRIP "$IPK_DIR/data/usr/lib/libcares.so"*

cat > "$IPK_DIR/control" << 'EOF'
Package: libcares
Version: 1.34.6-1
Architecture: aarch64_cortex-a53
Maintainer: RouterAssistant
Section: libs
Priority: optional
Depends: libc
Description: Asynchronous DNS resolver library (C library)
 c-ares is a C library for asynchronous DNS requests.
 This package provides version 1.34.6 required by https-dns-proxy.
EOF

cd "$IPK_DIR"
tar czf ../control.tar.gz ./control
tar czf ../data.tar.gz -C data .
echo "2.0" > ../debian-binary
ar r "../$IPK_NAME" debian-binary control.tar.gz data.tar.gz

cp "../$IPK_NAME" "$PACKAGES_DIR/"

echo ""
echo "========================================="
echo "  编译完成！"
echo "========================================="
ls -lh "$PACKAGES_DIR/$IPK_NAME"
echo ""
echo "文件已复制到: $PACKAGES_DIR/$IPK_NAME"
