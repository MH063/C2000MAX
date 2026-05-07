include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-router-assistant
PKG_VERSION:=$(shell grep '"version"' $(CURDIR)/version.json 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "1.0.44")
PKG_RELEASE:=1
PKG_ARCH:=aarch64_cortex-a53
PKG_CATEGORIES:=luci
PKG_MAINTAINER:=MH
PKG_DESCRIPTION:=RouterAssistant - Network Management LuCI Application

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-router-assistant
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=RouterAssistant
  TITLE:=RouterAssistant
  DEPENDS:=+luci-base +libiwinfo +ipset +iptables +liblua +libuci
  PKGARCH:=$(PKG_ARCH)
endef

define Package/luci-app-router-assistant/description
 路由助手 - 网络管理和流量统计工具
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-router-assistant/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model
	$(INSTALL_DIR) $(1)/usr/libexec/router_assistant
	$(INSTALL_DIR) $(1)/usr/share/router-assistant
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/www/lu-static
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DIR) $(1)/usr/share/router-assistant/packages

	$(CP) ./luasrc/controller/* $(1)/usr/lib/lua/luci/controller/
	$(CP) ./luasrc/view/* $(1)/usr/lib/lua/luci/view/
	$(CP) ./luasrc/model/* $(1)/usr/lib/lua/luci/model/
	$(CP) ./htdocs/* $(1)/www/lu-static/
	$(CP) ./rootfs/* $(1)/
	$(CP) ./scripts/collect_traffic.lua $(1)/usr/libexec/router_assistant/
	chmod 755 $(1)/usr/libexec/router_assistant/collect_traffic.lua
	$(CP) ./scripts/timeout_aarch64 $(1)/usr/libexec/router_assistant/timeout
	chmod 755 $(1)/usr/libexec/router_assistant/timeout
	$(CP) ./version.json $(1)/usr/share/router-assistant/
	$(CP) ./luasrc/oui_database.json $(1)/usr/share/router-assistant/
	$(CP) ./etc/init.d/traffic-stats $(1)/etc/init.d/
	$(CP) ./usr/share/luci/menu.d/* $(1)/usr/share/luci/menu.d/

	# 内置DNS加密依赖包
	$(CP) ./files/packages/*.ipk $(1)/usr/share/router-assistant/packages/
	$(CP) ./files/packages/timeout_aarch64 $(1)/usr/libexec/router_assistant/timeout_aarch64
	chmod 755 $(1)/usr/libexec/router_assistant/timeout_aarch64

	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/traffic-stats $(1)/etc/rc.d/S95traffic-stats
endef

define Package/luci-app-router-assistant/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# 平滑升级：只清理缓存，保留所有历史数据和配置
	echo "router-assistant: 正在执行安装后处理..."

	# 1. 清理 LuCI 缓存（确保新界面生效）
	rm -f /tmp/luci-indexcache

	# 2. 只清理临时缓存文件，保留核心数据
	for dir in /tmp/storage /mnt/mmcblk0p1 /mnt/sdcard /tmp; do
		[ -d "${dir}" ] || continue
		for subdir in router_assistant tmp/router_assistant; do
			if [ -d "${dir}/${subdir}" ]; then
				# 只删除临时缓存，保留：current.json, traffic_monthly.json,
				# mac_blocklist.json, baseline.json, daily/weekly/monthly/backup/
				rm -f "${dir}/${subdir}/blocked_macs_cache.json" 2>/dev/null
				rm -f "${dir}/${subdir}/traffic_stats.json" 2>/dev/null
				rm -f "${dir}/${subdir}/traffic_hourly.json" 2>/dev/null
			fi
		done
	done

	# 3. 自动安装DNS加密依赖包（如果未安装）
	PKG_DIR="/usr/share/router-assistant/packages"
	if [ -d "$PKG_DIR" ]; then
		echo "router-assistant: 检查DNS加密依赖包..."
		for ipk in "$PKG_DIR"/*.ipk; do
			[ -f "$ipk" ] || continue
			pkg_name=$(basename "$ipk" .ipk | sed 's/_.*//')
			# 检查是否已安装（处理带版本号的包名如 getdns_1.7.0-1）
			pkg_base=$(echo "$pkg_name" | cut -d'_' -f1)
			if ! opkg list-installed 2>/dev/null | grep -q "^${pkg_base} "; then
				echo "router-assistant: 安装依赖 $ipk ..."
				opkg install --force-reinstall "$ipk" 2>/dev/null || \
				opkg install "$ipk" 2>/dev/null || \
				echo "router-assistant: 警告 - $pkg_name 安装失败"
			else
				echo "router-assistant: $pkg_base 已安装，跳过"
			fi
		done
	fi

	# 4. 设置timeout命令权限
	if [ -f "/usr/libexec/router_assistant/timeout_aarch64" ]; then
		chmod 755 /usr/libexec/router_assistant/timeout_aarch64
	fi

	# 5. 重启服务以加载新的脚本和规则
	/etc/init.d/traffic-stats restart 2>/dev/null

	echo "router-assistant: 安装完成（历史数据已保留）"
}
exit 0
endef

define Package/luci-app-router-assistant/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
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
	if [ -f "$$CRON_FILE" ]; then
		sed -i '/collect_traffic/d' "$$CRON_FILE" 2>/dev/null
		sed -i '/router_assistant/d' "$$CRON_FILE" 2>/dev/null
		sed -i '/traffic_stats/d' "$$CRON_FILE" 2>/dev/null
	fi
	echo "路由管家: cron 任务已清理"
	
	# 清理 LuCI 缓存
	rm -f /tmp/luci-indexcache 2>/dev/null
	rm -rf /tmp/luci-modulecache 2>/dev/null
	echo "路由管家: LuCI 缓存已清理"
	
	# 清理流量统计数据
	RA_DATA_DIR="/mnt/mmcblk0p1/router_assistant"
	[ ! -d "$$RA_DATA_DIR" ] && RA_DATA_DIR="/mnt/sdcard/router_assistant"
	if [ -d "$$RA_DATA_DIR" ]; then
		rm -f "$$RA_DATA_DIR/current.json" 2>/dev/null
		rm -f "$$RA_DATA_DIR/traffic_monthly.json" 2>/dev/null
		rm -f "$$RA_DATA_DIR/hourly_snapshot.json" 2>/dev/null
		rm -rf "$$RA_DATA_DIR/daily" 2>/dev/null
		rm -rf "$$RA_DATA_DIR/weekly" 2>/dev/null
		rm -rf "$$RA_DATA_DIR/monthly" 2>/dev/null
		rm -rf "$$RA_DATA_DIR/backup" 2>/dev/null
	fi
	echo "路由管家: 流量统计数据已清理"
	
	# 清理黑名单
	rm -f "$$RA_DATA_DIR/mac_blocklist.json" 2>/dev/null
	echo "路由管家: 黑名单已清理"
	
	# 恢复DNS配置（防止卸载后DNS无法解析）
	echo "路由管家: 恢复DNS配置..."
	if [ -f "/etc/config/dhcp" ]; then
		uci -q delete dhcp.@dnsmasq[0].noresolv
		uci -q delete dhcp.@dnsmasq[0].localuse
		server_idx=0
		while uci -q get dhcp.@dnsmasq[0].server >/dev/null 2>&1; do
			uci -q delete dhcp.@dnsmasq[0].server 2>/dev/null
			server_idx=$$((server_idx + 1))
			[ $$server_idx -gt 10 ] && break
		done
		uci -q set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
		uci commit dhcp
		/etc/init.d/dnsmasq restart 2>/dev/null
		echo "路由管家: DNS配置已恢复"
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
	if pidof stubby >/dev/null 2>&1; then
		kill -9 $(pidof stubby) 2>/dev/null
	fi
	if pidof https-dns-proxy >/dev/null 2>&1; then
		kill -9 $(pidof https-dns-proxy) 2>/dev/null
	fi
	echo "路由管家: DNS加密服务已停止"
	
	# 删除DNS加密依赖包文件
	echo "路由管家: 正在删除DNS加密依赖包..."
	rm -f /usr/sbin/stubby 2>/dev/null
	rm -f /usr/bin/stubby 2>/dev/null
	rm -f /etc/init.d/stubby 2>/dev/null
	rm -f /etc/config/stubby 2>/dev/null
	rm -rf /etc/stubby 2>/dev/null
	rm -f /usr/lib/opkg/info/stubby.* 2>/dev/null
	rm -f /var/run/stubby.pid 2>/dev/null
	
	rm -f /usr/sbin/https-dns-proxy 2>/dev/null
	rm -f /usr/bin/https-dns-proxy 2>/dev/null
	rm -f /etc/init.d/https-dns-proxy 2>/dev/null
	rm -f /etc/config/https-dns-proxy 2>/dev/null
	rm -f /usr/lib/opkg/info/https-dns-proxy.* 2>/dev/null
	rm -f /var/run/https-dns-proxy.pid 2>/dev/null
	
	rm -f /usr/lib/libgetdns.so* 2>/dev/null
	rm -f /usr/lib/opkg/info/getdns.* 2>/dev/null
	rm -f /usr/lib/libcares.so* 2>/dev/null
	rm -f /usr/lib/opkg/info/libcares.* 2>/dev/null
	rm -f /usr/lib/libev.so* 2>/dev/null
	rm -f /usr/lib/opkg/info/libev.* 2>/dev/null
	
	rm -rf /usr/share/router-assistant/packages 2>/dev/null
	echo "路由管家: DNS加密依赖包已删除"
	
	# 清理防火墙重启钩子
	rm -f /etc/hotplug.d/firewall/99-traffic-stats 2>/dev/null
	rm -f /etc/hotplug.d/firewall/98-rate-limit-restore 2>/dev/null
	# 清理 firewall.user 中的钩子（清理所有路由管家相关的行及其前后的空行）
	sed -i '/# 路由管家/d' /etc/firewall.user 2>/dev/null
	sed -i '/traffic-stats restart/d' /etc/firewall.user 2>/dev/null
	sed -i '/路由管家.*防火墙启动后自动重启流量统计/d' /etc/firewall.user 2>/dev/null
	# 清理可能残留的空行（连续多个空行合并为一个）
	sed -i '/^$/N;/^\n$/D' /etc/firewall.user 2>/dev/null
	echo "路由管家: 防火墙钩子已清理"
	
	echo "路由管家: 卸载前脚本执行完成"
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-router-assistant))