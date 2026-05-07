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
# 路由管家 - 安装后脚本
# 功能：初始化服务 + 安装依赖包
# ============================================================

echo "路由管家: 正在执行安装后脚本..."

# 修复旧版本prerm脚本的local关键字问题（如果存在）
OLD_PRERM="/usr/lib/opkg/info/路由管家.prerm"
if [ -f "$OLD_PRERM" ]; then
    if grep -q "local server_idx\|local srv=" "$OLD_PRERM" 2>/dev/null; then
        echo "路由管家: 修复旧版prerm脚本..."
        sed -i 's/local server_idx/server_idx/g' "$OLD_PRERM"
        sed -i 's/local srv=/srv=/g' "$OLD_PRERM"
        echo "路由管家: prerm脚本已修复"
    fi
fi

# --- 第一步：停止旧版服务 ---
/etc/init.d/traffic-stats stop 2>/dev/null
echo "路由管家: 旧版服务已停止"

# --- 第二步：清理旧版DNS加密依赖包（解决升级安装时旧版本未清理的问题）---
echo "路由管家: 正在清理旧版DNS加密依赖包..."

# 停止DNS加密服务
/etc/init.d/stubby stop 2>/dev/null
/etc/init.d/stubby disable 2>/dev/null
/etc/init.d/https-dns-proxy stop 2>/dev/null
/etc/init.d/https-dns-proxy disable 2>/dev/null

# 强制杀死残留进程（init.d stop可能无法完全停止）
sleep 1
killall stubby 2>/dev/null
killall https-dns-proxy 2>/dev/null
sleep 1
if pidof stubby >/dev/null 2>&1; then
    kill -9 $(pidof stubby) 2>/dev/null
fi
if pidof https-dns-proxy >/dev/null 2>&1; then
    kill -9 $(pidof https-dns-proxy) 2>/dev/null
fi

# 删除 stubby 相关文件
rm -f /usr/sbin/stubby 2>/dev/null
rm -f /usr/bin/stubby 2>/dev/null
rm -f /etc/init.d/stubby 2>/dev/null
rm -f /etc/config/stubby 2>/dev/null
rm -rf /etc/stubby 2>/dev/null
rm -f /usr/lib/opkg/info/stubby.* 2>/dev/null
rm -f /var/run/stubby.pid 2>/dev/null

# 删除 https-dns-proxy 相关文件
rm -f /usr/sbin/https-dns-proxy 2>/dev/null
rm -f /usr/bin/https-dns-proxy 2>/dev/null
rm -f /etc/init.d/https-dns-proxy 2>/dev/null
rm -f /etc/config/https-dns-proxy 2>/dev/null
rm -f /usr/lib/opkg/info/https-dns-proxy.* 2>/dev/null
rm -f /var/run/https-dns-proxy.pid 2>/dev/null

# 删除 getdns 库文件
rm -f /usr/lib/libgetdns.so* 2>/dev/null
rm -f /usr/lib/opkg/info/getdns.* 2>/dev/null

# 删除 libcares 库文件
rm -f /usr/lib/libcares.so* 2>/dev/null
rm -f /usr/lib/opkg/info/libcares.* 2>/dev/null

# 删除 libev 库文件
rm -f /usr/lib/libev.so* 2>/dev/null
rm -f /usr/lib/opkg/info/libev.* 2>/dev/null

echo "路由管家: 旧版DNS加密依赖包已清理"

# --- 第三步：清理旧版运行时状态 ---
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
    echo "# 路由管家: 防火墙启动后延迟重启流量统计（避免竞态条件）" >> /etc/firewall.user
    echo "(sleep 5 && /etc/init.d/traffic-stats restart) >/dev/null 2>&1 &" >> /etc/firewall.user
    echo "路由管家: firewall.user 钩子已添加"
fi

# 方法2: 使用 hotplug（备用）
mkdir -p /etc/hotplug.d/firewall
cat > /etc/hotplug.d/firewall/99-traffic-stats << 'HOTPLUG'
#!/bin/sh
# 防火墙重启后延迟重启流量统计服务（避免与防火墙初始化冲突）
case "$ACTION" in
    restart|start|ifup)
        logger -t traffic-stats "Firewall $ACTION detected, scheduling traffic-stats restart in 5s..."
        # 延迟5秒执行，确保防火墙规则完全加载
        (sleep 5 && /etc/init.d/traffic-stats restart) >/dev/null 2>&1 &
        ;;
esac
HOTPLUG
chmod +x /etc/hotplug.d/firewall/99-traffic-stats
echo "路由管家: 防火墙重启钩子已创建"

# --- 手动安装DNS加密依赖包（不使用opkg）---
echo "路由管家: 检查DNS加密依赖包..."
PKG_DIR="/usr/share/router-assistant/packages"
if [ -d "$PKG_DIR" ]; then
    for ipk in "$PKG_DIR"/*.ipk; do
        [ -f "$ipk" ] || continue
        pkg_name=$(basename "$ipk" .ipk)
        pkg_base=$(echo "$pkg_name" | sed 's/_.*//')
        
        # 检查关键文件是否存在（而非查询opkg数据库）
        case $pkg_base in
            stubby) check_file="/usr/sbin/stubby" ;;
            https-dns-proxy) check_file="/usr/sbin/https-dns-proxy" ;;
            libcares) check_file="/usr/lib/libcares.so.2" ;;
            getdns) check_file="/usr/lib/libgetdns.so.10" ;;
            libev) check_file="/usr/lib/libev.so.4" ;;
            *) check_file="" ;;
        esac
        
        if [ -n "$check_file" ] && [ ! -f "$check_file" ]; then
            echo "路由管家: 手动安装依赖 $pkg_base ..."
            
            # 创建临时目录
            tmp_dir="/tmp/ipk_install_$pkg_base"
            rm -rf "$tmp_dir" 2>/dev/null
            mkdir -p "$tmp_dir"
            
            # 解压IPK文件
            if cd "$tmp_dir" && tar xzf "$ipk" 2>/dev/null; then
                # 提取程序数据到根目录
                [ -f data.tar.gz ] && tar xzf data.tar.gz -C / 2>/dev/null
                
                # 提取控制信息
                mkdir -p /usr/lib/opkg/info 2>/dev/null
                [ -f control.tar.gz ] && tar xzf control.tar.gz -C /usr/lib/opkg/info/ 2>/dev/null
                
                # 执行安装后脚本
                [ -f control/postinst ] && sh control/postinst install 2>/dev/null
                
                echo "路由管家: $pkg_base 安装完成"
            else
                echo "路由管家: 警告 - $pkg_base 解压失败"
            fi
            
            # 清理临时目录
            rm -rf "$tmp_dir" 2>/dev/null
        else
            echo "路由管家: $pkg_base 已安装，跳过"
        fi
    done
else
    echo "路由管家: 未找到依赖包目录"
fi

# 设置timeout命令权限
if [ -f "/usr/libexec/router_assistant/timeout" ]; then
    chmod 755 /usr/libexec/router_assistant/timeout
    echo "路由管家: timeout权限已设置"
fi

# 设置 OpenSSL 3.0.0 库文件权限并更新链接缓存
if [ -f "/usr/lib/libssl.so.3" ]; then
    chmod 755 /usr/lib/libssl.so.3
    echo "路由管家: libssl.so.3 权限已设置"
fi
if [ -f "/usr/lib/libcrypto.so.3" ]; then
    chmod 755 /usr/lib/libcrypto.so.3
    echo "路由管家: libcrypto.so.3 权限已设置"
fi

# 更新动态链接库缓存
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
    echo "路由管家: 动态链接库缓存已更新"
fi

# --- 第九步：初始化 DNSSEC 安全验证工具 ---
echo "路由管家: 正在初始化 DNSSEC 安全验证工具..."

DNSSEC_DIR="/usr/share/router-assistant"
if [ -d "$DNSSEC_DIR" ]; then
    # 设置 DNSSEC 脚本权限
    if [ -f "$DNSSEC_DIR/check_dnssec.sh" ]; then
        chmod 755 "$DNSSEC_DIR/check_dnssec.sh"
        echo "路由管家: check_dnssec.sh 权限已设置 (DNSSEC状态检测)"
    fi
    
    if [ -f "$DNSSEC_DIR/getdns_query_tool.sh" ]; then
        chmod 755 "$DNSSEC_DIR/getdns_query_tool.sh"
        echo "路由管家: getdns_query_tool.sh 权限已设置 (getdns专业验证)"
    fi
    
    if [ -f "$DNSSEC_DIR/monitor_dnssec.sh" ]; then
        chmod 755 "$DNSSEC_DIR/monitor_dnssec.sh"
        echo "路由管家: monitor_dnssec.sh 权限已设置 (DNSSEC持续监控)"
    fi
    
    echo "路由管家: ✅ DNSSEC安全验证工具已就绪"
    echo "路由管家: 使用方法: sh $DNSSEC_DIR/check_dnssec.sh"
else
    echo "路由管家: ⚠️  DNSSEC工具目录不存在: $DNSSEC_DIR"
fi

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

# 恢复DNS配置（防止卸载后DNS无法解析）
echo "路由管家: 恢复DNS配置..."
if [ -f "/etc/config/dhcp" ]; then
    # 删除DNS加密相关的dnsmasq配置
    uci -q delete dhcp.@dnsmasq[0].noresolv
    uci -q delete dhcp.@dnsmasq[0].localuse
    
    # 删除所有server配置（包括127.0.0.1#5353和错误的配置）
    # 先获取所有server值，然后逐个删除
    server_idx=0
    while uci -q get dhcp.@dnsmasq[0].server >/dev/null 2>&1; do
        srv=$(uci -q get dhcp.@dnsmasq[0].server)
        if [ -n "$srv" ]; then
            echo "路由管家: 删除server配置: $srv"
            uci -q delete dhcp.@dnsmasq[0].server
        else
            break
        fi
        server_idx=$((server_idx + 1))
        # 防止无限循环
        if [ $server_idx -gt 10 ]; then
            break
        fi
    done
    
    # 确保resolvfile设置正确（使用默认的DNS）
    uci -q set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
    
    uci commit dhcp
    /etc/init.d/dnsmasq restart 2>/dev/null
    echo "路由管家: DNS配置已恢复，使用默认DNS"
fi

# 停止DNS加密服务
/etc/init.d/stubby stop 2>/dev/null
/etc/init.d/stubby disable 2>/dev/null
/etc/init.d/https-dns-proxy stop 2>/dev/null
/etc/init.d/https-dns-proxy disable 2>/dev/null

# 强制杀死残留进程（init.d stop可能无法完全停止）
sleep 1
killall stubby 2>/dev/null
killall https-dns-proxy 2>/dev/null
sleep 1
# 如果进程仍在运行，强制 kill -9
if pidof stubby >/dev/null 2>&1; then
    kill -9 $(pidof stubby) 2>/dev/null
fi
if pidof https-dns-proxy >/dev/null 2>&1; then
    kill -9 $(pidof https-dns-proxy) 2>/dev/null
fi
echo "路由管家: DNS加密服务已停止"

# 删除DNS加密依赖包文件（手动安装的非opkg包，需手动清理）
echo "路由管家: 正在删除DNS加密依赖包..."

# 删除 stubby 相关文件（可能安装在/usr/bin或/usr/sbin）
rm -f /usr/sbin/stubby 2>/dev/null
rm -f /usr/bin/stubby 2>/dev/null
rm -f /etc/init.d/stubby 2>/dev/null
rm -f /etc/config/stubby 2>/dev/null
rm -f /etc/stubby/stubby.yml 2>/dev/null
rm -rf /etc/stubby 2>/dev/null
rm -f /usr/lib/opkg/info/stubby.* 2>/dev/null
# 删除stubby可能创建的PID文件和日志
rm -f /var/run/stubby.pid 2>/dev/null
rm -f /var/log/stubby.log 2>/dev/null
echo "路由管家: stubby 已删除"

# 删除 https-dns-proxy 相关文件（可能安装在/usr/bin或/usr/sbin）
rm -f /usr/sbin/https-dns-proxy 2>/dev/null
rm -f /usr/bin/https-dns-proxy 2>/dev/null
rm -f /etc/init.d/https-dns-proxy 2>/dev/null
rm -f /etc/config/https-dns-proxy 2>/dev/null
rm -f /usr/lib/opkg/info/https-dns-proxy.* 2>/dev/null
# 删除https-dns-proxy可能创建的PID文件和日志
rm -f /var/run/https-dns-proxy.pid 2>/dev/null
rm -f /var/log/https-dns-proxy.log 2>/dev/null
echo "路由管家: https-dns-proxy 已删除"

# 删除 getdns 库文件
rm -f /usr/lib/libgetdns.so* 2>/dev/null
rm -f /usr/lib/opkg/info/getdns.* 2>/dev/null
echo "路由管家: getdns 已删除"

# 删除 libcares 库文件
rm -f /usr/lib/libcares.so* 2>/dev/null
rm -f /usr/lib/opkg/info/libcares.* 2>/dev/null
echo "路由管家: libcares 已删除"

# 删除 libev 库文件
rm -f /usr/lib/libev.so* 2>/dev/null
rm -f /usr/lib/opkg/info/libev.* 2>/dev/null
echo "路由管家: libev 已删除"

# 删除DNS加密依赖包目录
rm -rf /usr/share/router-assistant/packages 2>/dev/null

# 停止 DNSSEC 监控进程（如果正在运行）
if [ -f /tmp/dnssec_monitor.pid ]; then
    MONITOR_PID=$(cat /tmp/dnssec_monitor.pid)
    if kill -0 $MONITOR_PID 2>/dev/null; then
        kill $MONITOR_PID 2>/dev/null
        sleep 1
        kill -9 $MONITOR_PID 2>/dev/null
        echo "路由管家: DNSSEC监控进程已停止 (PID: $MONITOR_PID)"
    fi
    rm -f /tmp/dnssec_monitor.pid
fi

# 删除 DNSSEC 安全验证工具脚本
rm -f /usr/share/router-assistant/check_dnssec.sh 2>/dev/null
rm -f /usr/share/router-assistant/getdns_query_tool.sh 2>/dev/null
rm -f /usr/share/router-assistant/monitor_dnssec.sh 2>/dev/null
echo "路由管家: DNSSEC安全验证工具已删除"

# 清理 DNSSEC 日志文件
rm -f /tmp/dnssec_check.log 2>/dev/null
rm -f /tmp/dnssec_monitor.log 2>/dev/null
rm -f /tmp/dnssec_alerts.log 2>/dev/null
echo "路由管家: DNSSEC日志文件已清理"

# 清理可能残留的DNS加密相关配置
rm -f /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null
# 重启dnsmasq使DNS配置生效（在恢复DNS配置后已经重启，这里确保服务状态正确）

# 清理防火墙重启钩子
rm -f /etc/hotplug.d/firewall/99-traffic-stats 2>/dev/null
rm -f /etc/hotplug.d/firewall/98-rate-limit-restore 2>/dev/null
# 清理 firewall.user 中的钩子（清理所有路由管家相关的行及其前后的空行）
sed -i '/# 路由管家/d' /etc/firewall.user 2>/dev/null
sed -i '/traffic-stats restart/d' /etc/firewall.user 2>/dev/null
sed -i '/路由管家.*防火墙启动后自动重启流量统计/d' /etc/firewall.user 2>/dev/null
sed -i '/flow_offloading/d' /etc/firewall.user 2>/dev/null
sed -i '/路由管家.*关闭 Flow Offloading/d' /etc/firewall.user 2>/dev/null
# 清理可能残留的空行（连续多个空行合并为一个）
sed -i '/^$/N;/^\n$/D' /etc/firewall.user 2>/dev/null
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

# 复制 DNSSEC 验证工具脚本（纵深防御功能）
echo "=== 复制 DNSSEC 安全验证工具 ==="
if [ -f "$SCRIPT_DIR/check_dnssec.sh" ]; then
    cp "$SCRIPT_DIR/check_dnssec.sh" "$PKG_DIR/data/usr/share/router-assistant/"
    chmod 755 "$PKG_DIR/data/usr/share/router-assistant/check_dnssec.sh"
    echo "✅ check_dnssec.sh 已包含 (DNSSEC状态检测)"
else
    echo "⚠️  Warning: check_dnssec.sh not found"
fi

if [ -f "$SCRIPT_DIR/getdns_query_tool.sh" ]; then
    cp "$SCRIPT_DIR/getdns_query_tool.sh" "$PKG_DIR/data/usr/share/router-assistant/"
    chmod 755 "$PKG_DIR/data/usr/share/router-assistant/getdns_query_tool.sh"
    echo "✅ getdns_query_tool.sh 已包含 (getdns专业验证)"
else
    echo "⚠️  Warning: getdns_query_tool.sh not found"
fi

if [ -f "$SCRIPT_DIR/monitor_dnssec.sh" ]; then
    cp "$SCRIPT_DIR/monitor_dnssec.sh" "$PKG_DIR/data/usr/share/router-assistant/"
    chmod 755 "$PKG_DIR/data/usr/share/router-assistant/monitor_dnssec.sh"
    echo "✅ monitor_dnssec.sh 已包含 (DNSSEC持续监控)"
else
    echo "⚠️  Warning: monitor_dnssec.sh not found"
fi

echo "DNSSEC安全验证工具已集成完成"

# 复制DNS加密依赖包
mkdir -p "$PKG_DIR/data/usr/share/router-assistant/packages"
if [ -d "$SCRIPT_DIR/files/packages" ]; then
    cp "$SCRIPT_DIR/files/packages/"*.ipk "$PKG_DIR/data/usr/share/router-assistant/packages/" 2>/dev/null
    IPK_COUNT=$(ls "$PKG_DIR/data/usr/share/router-assistant/packages/"*.ipk 2>/dev/null | wc -l)
    echo "DNS加密依赖包: $IPK_COUNT 个IPK文件已包含"
    
    # 复制timeout工具（只保留一个文件，节省空间）
    if [ -f "$SCRIPT_DIR/files/packages/timeout_aarch64" ]; then
        cp "$SCRIPT_DIR/files/packages/timeout_aarch64" "$PKG_DIR/data/usr/libexec/router_assistant/timeout"
        chmod 755 "$PKG_DIR/data/usr/libexec/router_assistant/timeout"
        echo "timeout工具已包含（49KB）"
    fi
    
    # 复制 OpenSSL 3.0.0 库文件（DNS 加密依赖）
    mkdir -p "$PKG_DIR/data/usr/lib"
    if [ -f "$SCRIPT_DIR/files/packages/libssl.so.3" ]; then
        cp "$SCRIPT_DIR/files/packages/libssl.so.3" "$PKG_DIR/data/usr/lib/"
        chmod 755 "$PKG_DIR/data/usr/lib/libssl.so.3"
        echo "libssl.so.3 已包含（749KB）"
    fi
    if [ -f "$SCRIPT_DIR/files/packages/libcrypto.so.3" ]; then
        cp "$SCRIPT_DIR/files/packages/libcrypto.so.3" "$PKG_DIR/data/usr/lib/"
        chmod 755 "$PKG_DIR/data/usr/lib/libcrypto.so.3"
        echo "libcrypto.so.3 已包含（4.7MB）"
    fi
else
    echo "Warning: files/packages directory not found"
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

printf '2.0\n' > debian-binary

IPK_FILE="$OUTPUT_DIR/${PKG_DISPLAY_VERSION}.ipk"
rm -f "$IPK_FILE"

# 使用gzip格式（与温度监控.ipk相同）
tar -cf "$IPK_FILE" debian-binary control.tar.gz data.tar.gz
gzip "$IPK_FILE"
mv "$IPK_FILE.gz" "$IPK_FILE"

echo "IPK created: $IPK_FILE"
ls -lh "$IPK_FILE"

echo "=== Verifying IPK format ==="
file "$IPK_FILE"
echo "=== debian-binary content ==="
cat -A debian-binary | head -1

cd "$SCRIPT_DIR"
rm -rf "$PKG_DIR"

echo ""
echo "=== Done ==="
echo "Output (中文): $IPK_FILE"
echo "Output (English): $IPK_FILE_EN"
echo ""
echo "提示: 如果中文文件名安装失败，请使用英文版本: $IPK_FILE_EN"
