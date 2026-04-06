#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/测试文件"
PKG_DIR="$SCRIPT_DIR/ipk_build"

PKG_VERSION="1.0.1-1"
PKG_ARCH="aarch64_cortex-a53"
PKG_NAME="luci-app-router-assistant"

rm -rf "$PKG_DIR" "$OUTPUT_DIR"
mkdir -p "$PKG_DIR/CONTROL" "$PKG_DIR/data" "$OUTPUT_DIR"

echo "=== Step 1: Creating control files ==="

cat > "$PKG_DIR/CONTROL/control" << ENDCONTROL
Package: luci-app-router-assistant
Version: 1.0.1-1
Architecture: aarch64_cortex-a53
Maintainer: MH
Description: Router Assistant - Network management and traffic statistics tool
ENDCONTROL
echo "Created control file"

cat > "$PKG_DIR/CONTROL/postinst" << 'ENDPOSTINST'
#!/bin/sh
chmod +x /etc/init.d/traffic-stats 2>/dev/null
/etc/init.d/traffic-stats enable 2>/dev/null
/etc/init.d/traffic-stats start 2>/dev/null
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache

# ========== 设置 Homebox 测速工具 ==========
echo "正在配置 Homebox 测速工具..."

# 设置 Homebox 可执行权限
if [ -f "/usr/bin/homebox" ]; then
    chmod +x /usr/bin/homebox
    echo "Homebox 测速工具已就绪"
else
    echo "警告: Homebox 未找到，测速功能将不可用"
fi

# ========== 初始化数据存储目录 ==========
TF_MOUNT=""
for mp in /tmp/storage/mmcblk0p1 /mnt/mmcblk0p1 /mnt/sdcard /tmp/mnt/mmcblk0p1; do
    if [ -d "$mp" ] && [ -w "$mp" ]; then
        TF_MOUNT="$mp"
        break
    fi
done

STORAGE_DIR=""
if [ -n "$TF_MOUNT" ]; then
    STORAGE_DIR="$TF_MOUNT/router_assistant/data"
    mkdir -p "$STORAGE_DIR"
    chmod 755 "$STORAGE_DIR"
    echo "数据存储目录: $STORAGE_DIR (TF卡)"
else
    STORAGE_DIR="/tmp/router_assistant"
    mkdir -p "$STORAGE_DIR"
    chmod 755 "$STORAGE_DIR"
    echo "数据存储目录: $STORAGE_DIR (内存，重启丢失)"
fi

# 更新appcenter配置
uci -q batch <<EOF
delete appcenter.luci-app-router-assistant
set appcenter.luci-app-router-assistant=package
set appcenter.luci-app-router-assistant.name='luci-app-router-assistant'
set appcenter.luci-app-router-assistant.version='1.0.1-1'
set appcenter.luci-app-router-assistant.size='21702'
set appcenter.luci-app-router-assistant.status='1'
set appcenter.luci-app-router-assistant.has_luci='1'
set appcenter.luci-app-router-assistant.open='1'
delete appcenter.luci_app_router_assistant_list
set appcenter.luci_app_router_assistant_list=package_list
set appcenter.luci_app_router_assistant_list.name='luci-app-router-assistant'
set appcenter.luci_app_router_assistant_list.pkg_name='luci-app-router-assistant'
set appcenter.luci_app_router_assistant_list.parent='luci-app-router-assistant'
set appcenter.luci_app_router_assistant_list.size='21702'
set appcenter.luci_app_router_assistant_list.version='1.0.1-1'
set appcenter.luci_app_router_assistant_list.has_luci='1'
set appcenter.luci_app_router_assistant_list.type='1'
set appcenter.luci_app_router_assistant_list.luci_module_file='/usr/lib/lua/luci/controller/router_assistant.lua'
commit appcenter
EOF

exit 0
ENDPOSTINST
chmod 755 "$PKG_DIR/CONTROL/postinst"

cat > "$PKG_DIR/CONTROL/prerm" << 'ENDPRERM'
#!/bin/sh
/etc/init.d/traffic-stats stop 2>/dev/null
/etc/init.d/traffic-stats disable 2>/dev/null
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
exit 0
ENDPRERM
chmod 755 "$PKG_DIR/CONTROL/prerm"

echo "=== Step 2: Copying data files ==="

mkdir -p "$PKG_DIR/data/etc/init.d"
cp "$SCRIPT_DIR/etc/init.d/traffic-stats" "$PKG_DIR/data/etc/init.d/traffic-stats"
chmod 755 "$PKG_DIR/data/etc/init.d/traffic-stats"

mkdir -p "$PKG_DIR/data/usr/lib/lua/luci/controller"
cp "$SCRIPT_DIR/luasrc/controller/router_assistant.lua" "$PKG_DIR/data/usr/lib/lua/luci/controller/"

mkdir -p "$PKG_DIR/data/usr/lib/lua/luci/view/router_assistant"
cp "$SCRIPT_DIR/luasrc/view/router_assistant/panel.htm" "$PKG_DIR/data/usr/lib/lua/luci/view/router_assistant/"

mkdir -p "$PKG_DIR/data/usr/bin"
if [ -f "$SCRIPT_DIR/usr/bin/homebox" ]; then
    cp "$SCRIPT_DIR/usr/bin/homebox" "$PKG_DIR/data/usr/bin/homebox"
    chmod 755 "$PKG_DIR/data/usr/bin/homebox"
    echo "Homebox binary included"
else
    echo "Warning: Homebox binary not found at $SCRIPT_DIR/usr/bin/homebox"
fi

echo "Data files copied"
find "$PKG_DIR/data" -type f | wc -l
echo "files in data directory"

echo "=== Step 3: Creating tar files ==="
tar -C "$PKG_DIR/CONTROL" -czf "$PKG_DIR/control.tar.gz" .
echo "control.tar.gz created"

tar -C "$PKG_DIR/data" -czf "$PKG_DIR/data.tar.gz" .
echo "data.tar.gz created"

echo "=== Step 4: Creating IPK (gzip compressed tar format) ==="

cd "$PKG_DIR"

echo "2.0" > debian-binary

IPK_FILE="$OUTPUT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"
rm -f "$IPK_FILE"

tar -cf "$IPK_FILE" debian-binary control.tar.gz data.tar.gz
gzip "$IPK_FILE"
mv "$IPK_FILE.gz" "$IPK_FILE"

echo "IPK created"
ls -lh "$IPK_FILE"

echo "=== Verifying IPK format ==="
file "$IPK_FILE"

cd "$SCRIPT_DIR"
rm -rf "$PKG_DIR"

echo ""
echo "=== Done ==="
