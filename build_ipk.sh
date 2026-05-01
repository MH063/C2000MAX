#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
PKG_DIR="$SCRIPT_DIR/ipk_build"

VERSION_FILE="$SCRIPT_DIR/version.json"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: version.json not found at $VERSION_FILE"
    exit 1
fi

PKG_VERSION=$(grep '"version"' "$VERSION_FILE" | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_DISPLAY_NAME=$(grep '"name"' "$VERSION_FILE" | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_DESCRIPTION=$(grep '"description"' "$VERSION_FILE" | head -1 | sed 's/.*"description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
PKG_AUTHOR=$(grep '"author"' "$VERSION_FILE" | head -1 | sed 's/.*"author"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

if [ -z "$PKG_VERSION" ]; then
    echo "Error: Could not parse version from version.json"
    exit 1
fi

if [ -z "$PKG_DISPLAY_NAME" ]; then
    PKG_DISPLAY_NAME="路由管家"
fi

if [ -z "$PKG_DESCRIPTION" ]; then
    PKG_DESCRIPTION="网络管理工具"
fi

if [ -z "$PKG_AUTHOR" ]; then
    PKG_AUTHOR="MH"
fi

PKG_ARCH="aarch64_cortex-a53"
PKG_DISPLAY_VERSION="${PKG_DISPLAY_NAME}${PKG_VERSION}"

echo "=== Package Info ==="
echo "Name: $PKG_DISPLAY_NAME"
echo "Version: $PKG_VERSION"
echo "Display: $PKG_DISPLAY_VERSION"
echo "Author: $PKG_AUTHOR"

rm -rf "$PKG_DIR" "$OUTPUT_DIR"
mkdir -p "$PKG_DIR/CONTROL" "$PKG_DIR/data" "$OUTPUT_DIR"

echo "=== Step 1: Creating control files ==="

cat > "$PKG_DIR/CONTROL/control" << ENDCONTROL
Package: $PKG_DISPLAY_NAME
Version: $PKG_VERSION
Architecture: $PKG_ARCH
Maintainer: $PKG_AUTHOR
Description: $PKG_DESCRIPTION
ENDCONTROL
echo "Created control file"

cat > "$PKG_DIR/CONTROL/postinst" << 'ENDPOSTINST'
#!/bin/sh

# ============================================================
# 路由管家 - 安装后脚本 (版本: __PKG_VERSION__)
# 功能：清理旧版数据 + 初始化新版本
# ============================================================

echo "路由管家: 正在执行安装后脚本..."

# --- 第一步：停止旧版服务 ---
/etc/init.d/traffic-stats stop 2>/dev/null
echo "路由管家: 旧版服务已停止"

# --- 第二步：清理旧版运行时状态 ---
echo "路由管家: 正在清理旧版运行时状态..."

# 清理 ipset（旧版可能残留无效的计数器数据）
ipset destroy traffic_stats_rx 2>/dev/null
ipset destroy traffic_stats_tx 2>/dev/null
echo "路由管家: ipset 旧数据已清理"

# 清理 iptables mangle 链（旧版规则可能与新版不兼容）
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_TX 2>/dev/null
iptables -t mangle -F TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -F TRAFFIC_STATS_TX 2>/dev/null
iptables -t mangle -X TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -X TRAFFIC_STATS_TX 2>/dev/null
echo "路由管家: iptables 旧规则已清理"

# 清理旧版 cron 任务
CRON_FILE="/etc/crontabs/root"
if [ -f "$CRON_FILE" ]; then
    sed -i '/collect_traffic/d' "$CRON_FILE" 2>/dev/null
    sed -i '/router_assistant/d' "$CRON_FILE" 2>/dev/null
    sed -i '/traffic_stats/d' "$CRON_FILE" 2>/dev/null
fi
echo "路由管家: 旧版 cron 任务已清理"

# 清理 LuCI 缓存
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null
echo "路由管家: LuCI 缓存已清理"

# --- 第三步：清理旧版流量统计数据 ---
# 数据存储路径搜索（与 collect.lua / router_assistant.lua 保持一致）
DATA_DIR=""
STORAGE_BASE_PATHS="/tmp/storage/mmcblk0p1 /mnt/mmcblk0p1 /mnt/sdcard /tmp/mnt/mmcblk0p1 /overlay"
for base_path in $STORAGE_BASE_PATHS; do
    if [ -d "${base_path}/router_assistant" ] && [ -w "${base_path}/router_assistant" ]; then
        DATA_DIR="${base_path}/router_assistant"
        break
    fi
done
# 也检查 /tmp 路径
if [ -z "$DATA_DIR" ] && [ -d "/tmp/router_assistant" ]; then
    DATA_DIR="/tmp/router_assistant"
fi

if [ -n "$DATA_DIR" ]; then
    echo "路由管家: 发现数据目录: $DATA_DIR"

    # 备份用户配置（黑名单）到临时位置
    BLOCKLIST_BACKUP=""
    if [ -f "$DATA_DIR/mac_blocklist.json" ]; then
        BLOCKLIST_BACKUP="/tmp/router_assistant_blocklist_backup.json"
        cp "$DATA_DIR/mac_blocklist.json" "$BLOCKLIST_BACKUP" 2>/dev/null
        echo "路由管家: 已备份 MAC 黑名单配置"
    fi

    # 删除所有流量统计数据（格式可能不兼容，必须清理）
    rm -f "$DATA_DIR/current.json" 2>/dev/null
    rm -f "$DATA_DIR/traffic_stats.json" 2>/dev/null
    rm -f "$DATA_DIR/traffic_monthly.json" 2>/dev/null
    rm -f "$DATA_DIR/hourly_snapshot.json" 2>/dev/null
    rm -rf "$DATA_DIR/daily" 2>/dev/null
    rm -rf "$DATA_DIR/weekly" 2>/dev/null
    rm -rf "$DATA_DIR/monthly" 2>/dev/null
    rm -rf "$DATA_DIR/backup" 2>/dev/null
    echo "路由管家: 旧版流量统计数据已清理"

    # 恢复用户配置（黑名单）
    if [ -n "$BLOCKLIST_BACKUP" ] && [ -f "$BLOCKLIST_BACKUP" ]; then
        cp "$BLOCKLIST_BACKUP" "$DATA_DIR/mac_blocklist.json" 2>/dev/null
        rm -f "$BLOCKLIST_BACKUP" 2>/dev/null
        echo "路由管家: MAC 黑名单配置已恢复"
    fi
else
    echo "路由管家: 未发现旧版数据目录"

    # 检查 /tmp 下的临时数据
    rm -rf /tmp/router_assistant/current.json 2>/dev/null
    rm -rf /tmp/router_assistant/traffic_stats.json 2>/dev/null
    rm -rf /tmp/router_assistant/daily 2>/dev/null
    rm -rf /tmp/router_assistant/weekly 2>/dev/null
    rm -rf /tmp/router_assistant/monthly 2>/dev/null
    rm -rf /tmp/router_assistant/backup 2>/dev/null
    rm -rf /tmp/router_assistant/traffic_monthly.json 2>/dev/null
fi

# --- 第四步：初始化新版本 ---
echo "路由管家: 正在初始化新版本..."

chmod +x /etc/init.d/traffic-stats 2>/dev/null
/etc/init.d/traffic-stats enable 2>/dev/null
/etc/init.d/traffic-stats start 2>/dev/null
echo "路由管家: 服务已启动"

# --- 第六步：首次流量采集 ---
if [ -f "/usr/libexec/router_assistant/collect_traffic.lua" ]; then
    echo "路由管家: 正在执行首次流量采集..."
    /usr/bin/lua /usr/libexec/router_assistant/collect_traffic.lua >/dev/null 2>&1
    echo "路由管家: 首次流量采集完成"
fi

# --- 第七步：配置应用中心 ---
OLD_NAME="luci-app-router-assistant"

echo "路由管家: 正在清理旧版配置..."

OLD_SECS=$(uci show appcenter 2>/dev/null | grep "$OLD_NAME" | awk -F. '{print $2}' | sort -u)
if [ -n "$OLD_SECS" ]; then
    for sec in $OLD_SECS; do
        echo "删除旧配置: appcenter.$sec"
        uci delete "appcenter.$sec" 2>/dev/null || true
    done
    uci commit appcenter
    echo "旧版配置已清理"
else
    echo "未找到旧版配置"
fi

echo "路由管家: 正在配置 Homebox 测速工具..."

if [ -f "/usr/bin/homebox" ]; then
    chmod +x /usr/bin/homebox
    echo "Homebox 测速工具已就绪"
else
    echo "警告: Homebox 未找到，测速功能将不可用"
fi

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

PKG_SECTION=$(uci show appcenter 2>/dev/null | grep "路由管家" | head -1 | awk -F. '{print $2}')

if [ -n "$PKG_SECTION" ]; then
    echo "Found package section: $PKG_SECTION, updating..."
    uci set appcenter.$PKG_SECTION.name='路由管家'
    uci set appcenter.$PKG_SECTION.version="路由管家__PKG_VERSION__"
    uci set appcenter.$PKG_SECTION.icon='router_assistant.png'
    uci set appcenter.$PKG_SECTION.des='网络管理 - 设备列表、流量统计、WiFi管理'
    uci set appcenter.$PKG_SECTION.status='1'
    uci set appcenter.$PKG_SECTION.has_luci='1'
    uci set appcenter.$PKG_SECTION.open='1'
    echo "Package config updated"
else
    echo "Package section not found, adding new..."
    uci add appcenter package
    uci set appcenter.@package[-1].name='路由管家'
    uci set appcenter.@package[-1].version="路由管家__PKG_VERSION__"
    uci set appcenter.@package[-1].icon='router_assistant.png'
    uci set appcenter.@package[-1].des='网络管理 - 设备列表、流量统计、WiFi管理'
    uci set appcenter.@package[-1].status='1'
    uci set appcenter.@package[-1].has_luci='1'
    uci set appcenter.@package[-1].open='1'
    echo "New package config added"
fi

PLIST_SECTION=$(uci show appcenter 2>/dev/null | grep "路由管家" | grep "package_list" | head -1 | awk -F. '{print $2}')

if [ -n "$PLIST_SECTION" ]; then
    echo "Found package_list section: $PLIST_SECTION, updating..."
    uci set appcenter.$PLIST_SECTION.name='路由管家'
    uci set appcenter.$PLIST_SECTION.pkg_name='路由管家'
    uci set appcenter.$PLIST_SECTION.parent='路由管家'
    uci set appcenter.$PLIST_SECTION.icon='router_assistant.png'
    uci set appcenter.$PLIST_SECTION.version="路由管家__PKG_VERSION__"
    uci set appcenter.$PLIST_SECTION.has_luci='1'
    uci set appcenter.$PLIST_SECTION.type='1'
    uci set appcenter.$PLIST_SECTION.luci_module_file='/usr/lib/lua/luci/controller/router_assistant.lua'
    echo "Package_list config updated"
else
    echo "Package_list section not found, adding new..."
    uci add appcenter package_list
    uci set appcenter.@package_list[-1].name='路由管家'
    uci set appcenter.@package_list[-1].pkg_name='路由管家'
    uci set appcenter.@package_list[-1].parent='路由管家'
    uci set appcenter.@package_list[-1].icon='router_assistant.png'
    uci set appcenter.@package_list[-1].version="路由管家__PKG_VERSION__"
    uci set appcenter.@package_list[-1].has_luci='1'
    uci set appcenter.@package_list[-1].type='1'
    uci set appcenter.@package_list[-1].luci_module_file='/usr/lib/lua/luci/controller/router_assistant.lua'
    echo "New package_list config added"
fi

uci commit appcenter

# --- 第八步：创建防火墙重启钩子（自动重启流量统计）---
echo "路由管家: 正在创建防火墙重启钩子..."

# 方法1: 使用 firewall.user（最可靠）
if ! grep -q "traffic-stats restart" /etc/firewall.user 2>/dev/null; then
    echo "" >> /etc/firewall.user
    echo "# 路由管家: 防火墙启动后自动重启流量统计" >> /etc/firewall.user
    echo "/etc/init.d/traffic-stats restart &" >> /etc/firewall.user
    echo "路由管家: firewall.user 钩子已添加"
fi

# 方法2: 使用 hotplug（备用）
mkdir -p /etc/hotplug.d/firewall
cat > /etc/hotplug.d/firewall/99-traffic-stats << 'HOTPLUG'
#!/bin/sh
# 防火墙重启后自动重启流量统计服务
case "$ACTION" in
    restart|start|ifup)
        logger -t traffic-stats "Firewall $ACTION detected, restarting traffic-stats..."
        /etc/init.d/traffic-stats restart &
        ;;
esac
HOTPLUG
chmod +x /etc/hotplug.d/firewall/99-traffic-stats
echo "路由管家: 防火墙重启钩子已创建"

echo "路由管家: 安装后脚本执行完成"

exit 0
ENDPOSTINST

# 替换版本号占位符
sed -i "s/__PKG_VERSION__/${PKG_VERSION}/g" "$PKG_DIR/CONTROL/postinst"

chmod 755 "$PKG_DIR/CONTROL/postinst"

cat > "$PKG_DIR/CONTROL/prerm" << 'ENDPRERM'
#!/bin/sh

# ============================================================
# 路由管家 - 卸载前脚本
# 功能：停止服务 + 清理所有运行时状态和数据
# ============================================================

echo "路由管家: 正在执行卸载前脚本..."

# 停止服务
/etc/init.d/traffic-stats stop 2>/dev/null
/etc/init.d/traffic-stats disable 2>/dev/null
echo "路由管家: 服务已停止"

# 清理 ipset
ipset destroy traffic_stats_rx 2>/dev/null
ipset destroy traffic_stats_tx 2>/dev/null
ipset destroy traffic_stats_rx_ip 2>/dev/null
ipset destroy traffic_stats_rx_ip6 2>/dev/null
echo "路由管家: ipset 已清理"

# 清理 iptables mangle 链
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_TX 2>/dev/null
iptables -t mangle -D POSTROUTING -j TRAFFIC_STATS_RX_IP 2>/dev/null
iptables -t mangle -F TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -F TRAFFIC_STATS_TX 2>/dev/null
iptables -t mangle -F TRAFFIC_STATS_RX_IP 2>/dev/null
iptables -t mangle -X TRAFFIC_STATS_RX 2>/dev/null
iptables -t mangle -X TRAFFIC_STATS_TX 2>/dev/null
iptables -t mangle -X TRAFFIC_STATS_RX_IP 2>/dev/null
echo "路由管家: iptables 规则已清理"

# 清理 ip6tables mangle 链
ip6tables -t mangle -D POSTROUTING -j TRAFFIC_STATS_RX_IP 2>/dev/null
ip6tables -t mangle -F TRAFFIC_STATS_RX_IP 2>/dev/null
ip6tables -t mangle -X TRAFFIC_STATS_RX_IP 2>/dev/null
echo "路由管家: ip6tables 规则已清理"

# 清理 cron 任务
CRON_FILE="/etc/crontabs/root"
if [ -f "$CRON_FILE" ]; then
    sed -i '/collect_traffic/d' "$CRON_FILE" 2>/dev/null
    sed -i '/router_assistant/d' "$CRON_FILE" 2>/dev/null
    sed -i '/traffic_stats/d' "$CRON_FILE" 2>/dev/null
fi
echo "路由管家: cron 任务已清理"

# 清理 LuCI 缓存
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null

# 清理流量统计数据（卸载时删除所有数据）
DATA_DIR=""
STORAGE_BASE_PATHS="/tmp/storage/mmcblk0p1 /mnt/mmcblk0p1 /mnt/sdcard /tmp/mnt/mmcblk0p1 /overlay"
for base_path in $STORAGE_BASE_PATHS; do
    if [ -d "${base_path}/router_assistant" ]; then
        DATA_DIR="${base_path}/router_assistant"
        break
    fi
done

if [ -n "$DATA_DIR" ]; then
    # 删除流量统计数据
    rm -f "$DATA_DIR/current.json" 2>/dev/null
    rm -f "$DATA_DIR/traffic_monthly.json" 2>/dev/null
    rm -f "$DATA_DIR/hourly_snapshot.json" 2>/dev/null
    rm -rf "$DATA_DIR/daily" 2>/dev/null
    rm -rf "$DATA_DIR/weekly" 2>/dev/null
    rm -rf "$DATA_DIR/monthly" 2>/dev/null
    rm -rf "$DATA_DIR/backup" 2>/dev/null
    # 删除黑名单
    rm -f "$DATA_DIR/mac_blocklist.json" 2>/dev/null
    echo "路由管家: 数据目录已清理: $DATA_DIR"
fi

# 清理 /tmp 下的临时数据
rm -rf /tmp/router_assistant 2>/dev/null

# 清理防火墙重启钩子
rm -f /etc/hotplug.d/firewall/99-traffic-stats 2>/dev/null
rm -f /etc/hotplug.d/firewall/98-rate-limit-restore 2>/dev/null
# 清理 firewall.user 中的钩子
sed -i '/traffic-stats restart/d' /etc/firewall.user 2>/dev/null
sed -i '/路由管家.*防火墙启动后自动重启流量统计/d' /etc/firewall.user 2>/dev/null
sed -i '/flow_offloading/d' /etc/firewall.user 2>/dev/null
sed -i '/路由管家.*关闭 Flow Offloading/d' /etc/firewall.user 2>/dev/null
echo "路由管家: 防火墙钩子已清理"

echo "路由管家: 卸载前脚本执行完成"

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

mkdir -p "$PKG_DIR/data/usr/libexec/router_assistant"
if [ -f "$SCRIPT_DIR/scripts/collect_traffic.lua" ]; then
    cp "$SCRIPT_DIR/scripts/collect_traffic.lua" "$PKG_DIR/data/usr/libexec/router_assistant/"
    chmod 755 "$PKG_DIR/data/usr/libexec/router_assistant/collect_traffic.lua"
    echo "Collect traffic script included"
else
    echo "Warning: collect_traffic.lua not found at $SCRIPT_DIR/scripts/collect_traffic.lua"
fi

if [ -f "$SCRIPT_DIR/scripts/timeout_aarch64" ]; then
    cp "$SCRIPT_DIR/scripts/timeout_aarch64" "$PKG_DIR/data/usr/libexec/router_assistant/timeout"
    chmod 755 "$PKG_DIR/data/usr/libexec/router_assistant/timeout"
    echo "Timeout binary included"
else
    echo "Warning: timeout_aarch64 not found at $SCRIPT_DIR/scripts/timeout_aarch64"
fi

if [ -f "$SCRIPT_DIR/usr/share/icons/router_assistant.svg" ]; then
    mkdir -p "$PKG_DIR/data/usr/share/icons"
    cp "$SCRIPT_DIR/usr/share/icons/router_assistant.svg" "$PKG_DIR/data/usr/share/icons/"
    echo "Icon file included"
else
    echo "Warning: Icon file not found at $SCRIPT_DIR/usr/share/icons/router_assistant.svg"
fi

if [ -f "$SCRIPT_DIR/usr/share/icons/router_assistant.png" ]; then
    mkdir -p "$PKG_DIR/data/www/luci-static/nradio/images/icon"
    cp "$SCRIPT_DIR/usr/share/icons/router_assistant.png" "$PKG_DIR/data/www/luci-static/nradio/images/icon/router_assistant.png"
    echo "PNG icon for appcenter included"
else
    echo "Note: PNG icon not found, appcenter may show default icon"
fi

# 复制 version.json
mkdir -p "$PKG_DIR/data/usr/share/router-assistant"
if [ -f "$SCRIPT_DIR/version.json" ]; then
    cp "$SCRIPT_DIR/version.json" "$PKG_DIR/data/usr/share/router-assistant/"
    echo "version.json included"
else
    echo "Warning: version.json not found"
fi

# 复制 oui_database.json
if [ -f "$SCRIPT_DIR/luasrc/oui_database.json" ]; then
    cp "$SCRIPT_DIR/luasrc/oui_database.json" "$PKG_DIR/data/usr/share/router-assistant/"
    echo "oui_database.json included"
else
    echo "Warning: oui_database.json not found"
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

IPK_FILE="$OUTPUT_DIR/${PKG_DISPLAY_VERSION}.ipk"
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
echo "Output: $IPK_FILE"
