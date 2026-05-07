#!/bin/bash
set -e

cd "/mnt/d/软件开发/MAX/路由管家/files/packages"

echo "=== 备份旧文件 ==="
for f in stubby.ipk getdns.ipk https-dns-proxy.ipk libcares.ipk libev.ipk; do
    if [ -f "$f" ]; then
        mv "$f" "$f.bak"
        echo "已备份: $f"
    fi
done

echo ""
echo "=== 下载新文件 ==="

echo "下载 getdns..."
wget -q --show-progress -O getdns.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/getdns_1.7.3-2_aarch64_cortex-a53.ipk'

echo "下载 https-dns-proxy..."
wget -q --show-progress -O https-dns-proxy.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/https-dns-proxy_2023.12.26-1_aarch64_cortex-a53.ipk'

echo "下载 libcares..."
wget -q --show-progress -O libcares.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/libcares_1.27.0-1_aarch64_cortex-a53.ipk'

echo "下载 libev..."
wget -q --show-progress -O libev.ipk 'https://downloads.openwrt.org/releases/23.05.5/packages/aarch64_cortex-a53/packages/libev_4.33-2_aarch64_cortex-a53.ipk'

echo "替换 stubby..."
mv stubby_new.ipk stubby.ipk

echo ""
echo "=== 完成！文件列表 ==="
ls -lh *.ipk

echo ""
echo "✅ 所有 IPK 包已更新为正确格式！"
