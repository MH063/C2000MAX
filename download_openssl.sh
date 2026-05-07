#!/bin/bash
set -e

cd "/mnt/d/软件开发/MAX/路由管家/files/packages"

echo "=== 下载 OpenSSL 相关包 ==="

# 下载 libopenssl3（OpenSSL 3.0 库）
echo "下载 libopenssl3..."
wget -q --show-progress -O libopenssl3.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/libopenssl3_3.1.5-1_aarch64_cortex-a53.ipk' || echo "⚠️ libopenssl3 下载失败，尝试其他版本..."

# 如果失败，尝试 libopenssl
if [ ! -f "libopenssl3.ipk" ] || [ ! -s "libopenssl3.ipk" ]; then
    echo "尝试下载 libopenssl..."
    wget -q --show-progress -O libopenssl.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/libopenssl_3.0.9-1_aarch64_cortex-a53.ipk' || echo "❌ libopenssl 下载失败"
fi

echo ""
echo "=== 检查已下载的文件 ==="
ls -lh *.ipk

echo ""
echo "✅ OpenSSL 包下载完成！"
