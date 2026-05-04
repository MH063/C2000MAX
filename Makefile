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
	echo "正在停止路由助手服务..."
	/etc/init.d/traffic-stats stop
	echo "iptables屏蔽规则已清除"
	echo ""
	echo "注意：屏蔽设备配置文件已保留在存储设备中"
	echo "如需完全清理，请手动删除："
	echo "  /mnt/mmcblk0p1/router_assistant/mac_blocklist.json"
	echo "  或 /mnt/sdcard/router_assistant/mac_blocklist.json"
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-router-assistant))