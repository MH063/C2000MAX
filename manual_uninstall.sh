#!/bin/bash

# ============================================================
# 路由管家 - 手动卸载脚本
# 功能：完全清理插件及所有相关文件
# 使用方法: sh manual_uninstall.sh
# ============================================================

set -e

echo "========================================="
echo "  路由管家 - 手动卸载工具"
echo "========================================="
echo ""

# 确认操作
read -p "确定要卸载路由管家吗？(y/N): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "已取消卸载"
    exit 0
fi

echo ""
echo "[1/5] 停止服务..."

# 停止流量统计服务
/etc/init.d/traffic-stats stop 2>/dev/null || true
/etc/init.d/traffic-stats disable 2>/dev/null || true
echo "✓ 流量统计服务已停止"

# 停止DNS加密服务
/etc/init.d/stubby stop 2>/dev/null || true
/etc/init.d/stubby disable 2>/dev/null || true
/etc/init.d/https-dns-proxy stop 2>/dev/null || true
/etc/init.d/https-dns-proxy disable 2>/dev/null || true

# 强制杀死残留进程（init.d stop可能无法完全停止）
sleep 1
killall stubby 2>/dev/null || true
killall https-dns-proxy 2>/dev/null || true
sleep 1
if pidof stubby >/dev/null 2>&1; then
    kill -9 $(pidof stubby) 2>/dev/null || true
fi
if pidof https-dns-proxy >/dev/null 2>&1; then
    kill -9 $(pidof https-dns-proxy) 2>/dev/null || true
fi
echo "✓ DNS加密服务已停止"

# 删除DNS加密依赖包文件（手动安装的非opkg包，需手动清理）
echo ""
echo "正在删除DNS加密依赖包..."

# 删除 stubby 相关文件（可能安装在/usr/bin或/usr/sbin）
rm -f /usr/sbin/stubby 2>/dev/null || true
rm -f /usr/bin/stubby 2>/dev/null || true
rm -f /etc/init.d/stubby 2>/dev/null || true
rm -f /etc/config/stubby 2>/dev/null || true
rm -f /etc/stubby/stubby.yml 2>/dev/null || true
rm -rf /etc/stubby 2>/dev/null || true
rm -f /usr/lib/opkg/info/stubby.* 2>/dev/null || true
# 删除stubby可能创建的PID文件和日志
rm -f /var/run/stubby.pid 2>/dev/null || true
rm -f /var/log/stubby.log 2>/dev/null || true
echo "✓ stubby 已删除"

# 删除 https-dns-proxy 相关文件（可能安装在/usr/bin或/usr/sbin）
rm -f /usr/sbin/https-dns-proxy 2>/dev/null || true
rm -f /usr/bin/https-dns-proxy 2>/dev/null || true
rm -f /etc/init.d/https-dns-proxy 2>/dev/null || true
rm -f /etc/config/https-dns-proxy 2>/dev/null || true
rm -f /usr/lib/opkg/info/https-dns-proxy.* 2>/dev/null || true
# 删除https-dns-proxy可能创建的PID文件和日志
rm -f /var/run/https-dns-proxy.pid 2>/dev/null || true
rm -f /var/log/https-dns-proxy.log 2>/dev/null || true
echo "✓ https-dns-proxy 已删除"

# 删除 getdns 库文件
rm -f /usr/lib/libgetdns.so* 2>/dev/null || true
rm -f /usr/lib/opkg/info/getdns.* 2>/dev/null || true
echo "✓ getdns 已删除"

# 删除 libcares 库文件
rm -f /usr/lib/libcares.so* 2>/dev/null || true
rm -f /usr/lib/opkg/info/libcares.* 2>/dev/null || true
echo "✓ libcares 已删除"

# 删除 libev 库文件
rm -f /usr/lib/libev.so* 2>/dev/null || true
rm -f /usr/lib/opkg/info/libev.* 2>/dev/null || true
echo "✓ libev 已删除"

# 删除DNS加密依赖包目录
rm -rf /usr/share/router-assistant/packages 2>/dev/null || true

# 清理可能残留的DNS加密相关配置
rm -f /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null || true

echo ""
echo "[2/5] 清理iptables/ipset规则..."

# 清理ipset
ipset destroy traffic_stats_rx 2>/dev/null || true
ipset destroy traffic_stats_tx 2>/dev/null || true
ipset destroy traffic_stats_rx_ip 2>/dev/null || true
ipset destroy traffic_stats_rx_ip6 2>/dev/null || true
echo "✓ ipset已清理"

# 清理iptables mangle链
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_RX 2>/dev/null || true
iptables -t mangle -D FORWARD -j TRAFFIC_STATS_TX 2>/dev/null || true
iptables -t mangle -D POSTROUTING -j TRAFFIC_STATS_RX_IP 2>/dev/null || true
iptables -t mangle -F TRAFFIC_STATS_RX 2>/dev/null || true
iptables -t mangle -F TRAFFIC_STATS_TX 2>/dev/null || true
iptables -t mangle -F TRAFFIC_STATS_RX_IP 2>/dev/null || true
iptables -t mangle -X TRAFFIC_STATS_RX 2>/dev/null || true
iptables -t mangle -X TRAFFIC_STATS_TX 2>/dev/null || true
iptables -t mangle -X TRAFFIC_STATS_RX_IP 2>/dev/null || true

# 清理ip6tables规则
ip6tables -t mangle -D POSTROUTING -j TRAFFIC_STATS_RX_IP 2>/dev/null || true
ip6tables -t mangle -F TRAFFIC_STATS_RX_IP 2>/dev/null || true
ip6tables -t mangle -X TRAFFIC_STATS_RX_IP 2>/dev/null || true
echo "✓ iptables/ip6tables规则已清理"

echo ""
echo "[3/5] 删除程序文件..."

# 删除主程序文件
rm -f /usr/lib/lua/luci/controller/router_assistant.lua 2>/dev/null
rm -rf /usr/lib/lua/luci/view/router_assistant 2>/dev/null
rm -f /etc/init.d/traffic-stats 2>/dev/null
rm -rf /usr/libexec/router_assistant 2>/dev/null
rm -f /usr/bin/homebox 2>/dev/null
rm -rf /usr/share/router-assistant 2>/dev/null
rm -f /usr/share/icons/router_assistant.svg 2>/dev/null
rm -f /www/luci-static/nradio/images/icon/router_assistant.png 2>/dev/null
echo "✓ 程序文件已删除"

echo ""
echo "[4/5] 清理配置和数据..."

# 删除opkg控制信息
rm -f /usr/lib/opkg/info/路由管家.control 2>/dev/null
rm -f /usr/lib/opkg/info/路由管家.postinst 2>/dev/null
rm -f /usr/lib/opkg/info/路由管家.prerm 2>/dev/null
rm -f /usr/lib/opkg/info/路由管家.conffiles 2>/dev/null
rm -f /usr/lib/opkg/info/路由管家.list 2>/dev/null
echo "✓ opkg控制信息已删除"

# 清理UCI配置（保留用户自定义配置）
if uci get router_assistant >/dev/null 2>&1; then
    uci delete router_assistant 2>/dev/null || true
    uci commit 2>/dev/null || true
    echo "✓ UCI配置已删除"
fi

# 清理应用中心配置
OLD_SECS=$(uci show appcenter 2>/dev/null | grep "路由管家" | awk -F. '{print $2}' | sort -u)
if [ -n "$OLD_SECS" ]; then
    for sec in $OLD_SECS; do
        uci delete "appcenter.$sec" 2>/dev/null || true
    done
    uci commit appcenter 2>/dev/null || true
    echo "✓ 应用中心配置已删除"
fi

# 清理流量统计数据
for base_path in /tmp/storage/mmcblk0p1 /mnt/mmcblk0p1 /mnt/sdcard /tmp/mnt/mmcblk0p1; do
    if [ -d "${base_path}/router_assistant" ]; then
        rm -rf "${base_path}/router_assistant" 2>/dev/null
        echo "✓ 数据目录已删除: ${base_path}/router_assistant"
        break
    fi
done

# 清理临时数据
rm -rf /tmp/router_assistant 2>/dev/null

# 清理cron任务
CRON_FILE="/etc/crontabs/root"
if [ -f "$CRON_FILE" ]; then
    sed -i '/collect_traffic/d' "$CRON_FILE" 2>/dev/null || true
    sed -i '/router_assistant/d' "$CRON_FILE" 2>/dev/null || true
    sed -i '/traffic_stats/d' "$CRON_FILE" 2>/dev/null || true
    echo "✓ cron任务已清理"
fi

# 清理LuCI缓存
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null
echo "✓ LuCI缓存已清理"

echo ""
echo "[5/5] 恢复DNS配置和防火墙钩子..."

# 恢复DNS配置
if [ -f "/etc/config/dhcp" ]; then
    uci -q delete dhcp.@dnsmasq[0].noresolv
    uci -q delete dhcp.@dnsmasq[0].localuse
    
    # 删除所有server配置
    idx=0
    while [ $idx -lt 10 ]; do
        srv=$(uci -q get dhcp.@dnsmasq[0].server)
        if [ -n "$srv" ]; then
            uci -q delete dhcp.@dnsmasq[0].server
        else
            break
        fi
        idx=$((idx + 1))
    done
    
    uci -q set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
    uci commit dhcp 2>/dev/null || true
    /etc/init.d/dnsmasq restart 2>/dev/null || true
    echo "✓ DNS配置已恢复"
fi

# 清理防火墙钩子
rm -f /etc/hotplug.d/firewall/99-traffic-stats 2>/dev/null
rm -f /etc/hotplug.d/firewall/98-rate-limit-restore 2>/dev/null
# 清理 firewall.user 中的钩子（清理所有路由管家相关的行及其前后的空行）
sed -i '/# 路由管家/d' /etc/firewall.user 2>/dev/null || true
sed -i '/traffic-stats restart/d' /etc/firewall.user 2>/dev/null || true
sed -i '/路由管家.*防火墙启动后自动重启流量统计/d' /etc/firewall.user 2>/dev/null || true
sed -i '/flow_offloading/d' /etc/firewall.user 2>/dev/null || true
sed -i '/路由管家.*关闭 Flow Offloading/d' /etc/firewall.user 2>/dev/null || true
# 清理可能残留的空行（连续多个空行合并为一个）
sed -i '/^$/N;/^\n$/D' /etc/firewall.user 2>/dev/null || true
echo "✓ 防火墙钩子已清理"

# 最终清理临时安装目录
rm -rf /tmp/ipk_install_* 2>/dev/null
rm -rf /tmp/router_assistant_install 2>/dev/null

echo ""
echo "========================================="
echo "  卸载完成！"
echo "========================================="
echo ""
echo "提示："
echo "  1. 请刷新浏览器清除缓存"
echo "  2. 如果DNS加密依赖包不再需要，可以手动删除："
echo "     - opkg remove stubby (如果通过opkg安装)"
echo "     - opkg remove https-dns-proxy (如果通过opkg安装)"
echo "  3. 或者保留依赖包供其他功能使用"
echo ""
