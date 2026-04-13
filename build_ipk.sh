#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
PKG_DIR="$SCRIPT_DIR/ipk_build"

# 从 version.json 读取版本信息
VERSION_FILE="$SCRIPT_DIR/version.json"
if [ ! -f "$VERSION_FILE" ]; then
    echo "错误: version.json 文件不存在"
    exit 1
fi

# 解析 version.json（使用 grep 和 sed，兼容性更好）
PKG_VERSION=$(grep '"version"' "$VERSION_FILE" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_DISPLAY_NAME=$(grep '"name"' "$VERSION_FILE" | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_AUTHOR=$(grep '"author"' "$VERSION_FILE" | sed 's/.*"author"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_DESCRIPTION=$(grep '"description"' "$VERSION_FILE" | sed 's/.*"description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

# 完整版本号（添加 -1 后缀）
FULL_VERSION="${PKG_VERSION}-1"
PKG_ARCH="aarch64_cortex-a53"
PKG_INTERNAL_NAME="luci-app-router-assistant"

echo "======================================="
echo "版本信息（来自 version.json）"
echo "======================================="
echo "名称: ${PKG_DISPLAY_NAME}"
echo "版本: ${PKG_VERSION}"
echo "完整版本: ${FULL_VERSION}"
echo "作者: ${PKG_AUTHOR}"
echo "描述: ${PKG_DESCRIPTION}"
echo "======================================="
echo ""

rm -rf "$PKG_DIR" "$OUTPUT_DIR"
mkdir -p "$PKG_DIR/CONTROL" "$PKG_DIR/data" "$OUTPUT_DIR"

echo "=== Step 1: Creating control files ==="

cat > "$PKG_DIR/CONTROL/control" << ENDCONTROL
Package: ${PKG_DISPLAY_NAME}
Version: ${PKG_VERSION}
Architecture: ${PKG_ARCH}
Maintainer: ${PKG_AUTHOR}
Description: ${PKG_DESCRIPTION}
ENDCONTROL
echo "Created control file"

cat > "$PKG_DIR/CONTROL/postinst" << 'ENDPOSTINST'
#!/bin/sh
chmod +x /etc/init.d/traffic-stats 2>/dev/null
/etc/init.d/traffic-stats enable 2>/dev/null
/etc/init.d/traffic-stats start 2>/dev/null
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache

# ========== 重启 uhttpd 使新代码生效 ==========
echo "正在重启 uhttpd 服务..."
if command -v uhttpd >/dev/null 2>&1; then
    /etc/init.d/uhttpd restart 2>/dev/null && echo "uhttpd 已重启" || echo "uhttpd 重启失败，将在新系统启动时生效"
fi

# ========== 设置 Homebox 测速工具 ==========
echo "正在配置 Homebox 测速工具..."

if [ -f "/usr/bin/homebox" ]; then
    chmod +x /usr/bin/homebox
    echo "Homebox 测速工具已就绪"
else
    echo "警告: Homebox 未找到，测速功能将不可用"
fi

# ========== 初始化数据存储目录 ==========
TF_MOUNT=""
for mp in /tmp/storage/mmcblk0p1 /mnt/mmcblk0p1 /mnt/sdcard /tmp/mnt/mmcblk0p1 /overlay; do
    if [ -d "$mp" ] && [ -w "$mp" ]; then
        TF_MOUNT="$mp"
        break
    fi
done

STORAGE_DIR=""
if [ -n "$TF_MOUNT" ]; then
    STORAGE_DIR="$TF_MOUNT/router_assistant"
    mkdir -p "$STORAGE_DIR"
    chmod 755 "$STORAGE_DIR"
    echo "数据存储目录: $STORAGE_DIR (持久化存储)"
else
    STORAGE_DIR="/tmp/router_assistant"
    mkdir -p "$STORAGE_DIR"
    chmod 755 "$STORAGE_DIR"
    echo "数据存储目录: $STORAGE_DIR (内存，重启丢失)"
fi

# ========== 检查必要服务 ==========
if ubus list infocd >/dev/null 2>&1; then
    : # infocd 服务正常
else
    echo "警告: infocd 服务未运行，部分功能可能受限"
fi

if [ ! -f "/usr/bin/access_ctl.sh" ]; then
    echo "提示: access_ctl.sh 未安装，ACL控制功能将不可用"
fi

# ========== 执行首次流量采集 ==========
if [ -f "/usr/libexec/router_assistant/collect_traffic.lua" ]; then
    chmod +x /usr/libexec/router_assistant/collect_traffic.lua
    if command -v ipset >/dev/null 2>&1; then
        echo "正在执行首次流量采集..."
        /usr/bin/lua /usr/libexec/router_assistant/collect_traffic.lua 2>/dev/null
        echo "首次流量采集完成"
    else
        echo "提示: ipset 未安装，跳过首次流量采集（不影响主要功能）"
    fi
else
    echo "警告: collect_traffic.lua 未找到"
fi

# ========== 更新appcenter配置（显示名称：路由管家+版本号）==========
uci -q batch <<EOF
delete appcenter.${PKG_INTERNAL_NAME}
set appcenter.${PKG_INTERNAL_NAME}=package
set appcenter.${PKG_INTERNAL_NAME}.name='${PKG_DISPLAY_NAME}${PKG_VERSION}'
set appcenter.${PKG_INTERNAL_NAME}.version='${PKG_VERSION}'
set appcenter.${PKG_INTERNAL_NAME}.size='21702'
set appcenter.${PKG_INTERNAL_NAME}.status='1'
set appcenter.${PKG_INTERNAL_NAME}.has_luci='1'
set appcenter.${PKG_INTERNAL_NAME}.open='1'
delete appcenter.${PKG_INTERNAL_NAME}_list
set appcenter.${PKG_INTERNAL_NAME}_list=package_list
set appcenter.${PKG_INTERNAL_NAME}_list.name='${PKG_DISPLAY_NAME}${PKG_VERSION}'
set appcenter.${PKG_INTERNAL_NAME}_list.pkg_name='${PKG_INTERNAL_NAME}'
set appcenter.${PKG_INTERNAL_NAME}_list.parent='${PKG_INTERNAL_NAME}'
set appcenter.${PKG_INTERNAL_NAME}_list.size='21702'
set appcenter.${PKG_INTERNAL_NAME}_list.version='${PKG_VERSION}'
set appcenter.${PKG_INTERNAL_NAME}_list.has_luci='1'
set appcenter.${PKG_INTERNAL_NAME}_list.type='1'
set appcenter.${PKG_INTERNAL_NAME}_list.luci_module_file='/usr/lib/lua/luci/controller/router_assistant.lua'
commit appcenter
EOF

exit 0
ENDPOSTINST

# 替换 postinst 中的变量占位符
sed -i "s/\${PKG_INTERNAL_NAME}/${PKG_INTERNAL_NAME}/g" "$PKG_DIR/CONTROL/postinst"
sed -i "s/\${PKG_VERSION}/${PKG_VERSION}/g" "$PKG_DIR/CONTROL/postinst"
sed -i "s/\${PKG_DISPLAY_NAME}/${PKG_DISPLAY_NAME}/g" "$PKG_DIR/CONTROL/postinst"
chmod 755 "$PKG_DIR/CONTROL/postinst"
sed -i 's/\r$//' "$PKG_DIR/CONTROL/postinst"

cat > "$PKG_DIR/CONTROL/prerm" << 'ENDPRERM'
#!/bin/sh
/etc/init.d/traffic-stats stop 2>/dev/null
/etc/init.d/traffic-stats disable 2>/dev/null
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
exit 0
ENDPRERM
chmod 755 "$PKG_DIR/CONTROL/prerm"
sed -i 's/\r$//' "$PKG_DIR/CONTROL/prerm"

echo "=== Step 2: Copying data files ==="

mkdir -p "$PKG_DIR/data/etc/init.d"
cp "$SCRIPT_DIR/etc/init.d/traffic-stats" "$PKG_DIR/data/etc/init.d/traffic-stats"
chmod 755 "$PKG_DIR/data/etc/init.d/traffic-stats"
sed -i 's/\r$//' "$PKG_DIR/data/etc/init.d/traffic-stats"

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

mkdir -p "$PKG_DIR/data/usr/lib/traffic_stats"
if [ -d "$SCRIPT_DIR/usr/lib/traffic_stats" ]; then
    cp "$SCRIPT_DIR/usr/lib/traffic_stats/"*.lua "$PKG_DIR/data/usr/lib/traffic_stats/" 2>/dev/null || true
    echo "Traffic stats scripts included"
fi

mkdir -p "$PKG_DIR/data/usr/libexec/router_assistant"
if [ -f "$SCRIPT_DIR/scripts/collect_traffic.lua" ]; then
    cp "$SCRIPT_DIR/scripts/collect_traffic.lua" "$PKG_DIR/data/usr/libexec/router_assistant/"
    chmod 755 "$PKG_DIR/data/usr/libexec/router_assistant/collect_traffic.lua"
    echo "Collect traffic script included"
else
    echo "Warning: collect_traffic.lua not found at $SCRIPT_DIR/scripts/collect_traffic.lua"
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

IPK_FILE="$OUTPUT_DIR/${PKG_DISPLAY_NAME}${PKG_VERSION}.ipk"
rm -f "$IPK_FILE"

tar -cf "$IPK_FILE" debian-binary control.tar.gz data.tar.gz
gzip "$IPK_FILE"
mv "$IPK_FILE.gz" "$IPK_FILE"

echo ""
echo "======================================="
echo "IPK 打包成功!"
echo "======================================="
ls -lh "$IPK_FILE"
echo ""

echo "=== Verifying IPK format ==="
file "$IPK_FILE"

cd "$SCRIPT_DIR"
rm -rf "$PKG_DIR"

echo ""
echo "=== Done ==="
echo ""
echo "输出文件: $IPK_FILE"
echo "显示名称: ${PKG_DISPLAY_NAME}${PKG_VERSION}"
