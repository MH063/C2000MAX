#!/bin/bash

set -e

PROJECT_DIR="/mnt/d/软件开发/MAX/路由管家"
SDK_DIR="$PROJECT_DIR/openwrt-sdk-21.02.0-mediatek-mt7622_gcc-8.4.0_musl.Linux-x86_64"
OUTPUT_DIR="$PROJECT_DIR/output"
PACKAGES_DIR="$PROJECT_DIR/files/packages"

echo "========================================="
echo "  libcares 1.34.6 编译脚本"
echo "========================================="

if [ ! -d "$SDK_DIR" ]; then
    echo "[错误] SDK目录不存在: $SDK_DIR"
    echo "请先解压SDK: tar -xf openwrt-sdk-*.tar.xz"
    exit 1
fi

echo "[1/6] 检查源码包..."
if [ ! -f "$PROJECT_DIR/c-ares-1.34.6.tar.gz" ]; then
    echo "[错误] 源码包不存在: c-ares-1.34.6.tar.gz"
    exit 1
fi
echo "      源码包存在 ✓"

echo "[2/6] 准备SDK环境..."
cd "$SDK_DIR"

if [ ! -f ".config" ]; then
    echo "      首次配置，运行defconfig..."
    make defconfig
fi

echo "[3/6] 复制Makefile到feeds..."
mkdir -p package/feeds/router-assistant
cp "$PROJECT_DIR/packages/libcares/Makefile" package/feeds/router-assistant/

echo "[4/6] 复制源码包到DL目录..."
cp "$PROJECT_DIR/c-ares-1.34.6.tar.gz dl/

echo "[5/6] 更新feeds并安装libcares..."
./scripts/feeds update packages 2>/dev/null || true
./scripts/feeds install libcares

echo "[6/6] 配置并编译libcares..."
echo "CONFIG_PACKAGE_libcares=y" >> .config
make defconfig

echo ""
echo "开始编译libcares (这可能需要几分钟)..."
make package/libcares/compile V=s

echo ""
echo "========================================="
echo "  查找生成的IPK包..."
echo "========================================="

find bin/packages -name "libcares_*.ipk" 2>/dev/null | while read ipk; do
    echo "找到: $ipk"
    ls -lh "$ipk"
    
    echo ""
    echo "复制到packages目录..."
    cp "$ipk" "$PACKAGES_DIR/"
    echo "已复制到: $PACKAGES_DIR/$(basename $ipk)"
done

echo ""
echo "========================================="
echo "  编译完成！"
echo "========================================="
ls -lh "$PACKAGES_DIR"/libcares*.ipk 2>/dev/null || echo "警告: 未找到libcares.ipk"
