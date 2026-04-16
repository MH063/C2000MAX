include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-router-assistant
PKG_VERSION:=1.0.0
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
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/ucode
	$(INSTALL_DIR) $(1)/usr/libexec/router_assistant
	$(INSTALL_DIR) $(1)/usr/share/router-assistant
	$(INSTALL_DIR) $(1)/usr/lib/traffic_stats
	$(INSTALL_DIR) $(1)/usr/lib/json
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/www/lu-static
	$(INSTALL_DIR) $(1)/usr/share/icons
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d

	$(CP) ./luasrc/controller/* $(1)/usr/lib/lua/luci/controller/
	$(CP) ./luasrc/view/* $(1)/usr/lib/lua/luci/view/
	$(CP) ./luasrc/model/* $(1)/usr/lib/lua/luci/model/
	$(CP) ./luasrc/ucode/* $(1)/usr/lib/lua/luci/ucode/
	$(CP) ./htdocs/* $(1)/www/lu-static/
	$(CP) ./rootfs/* $(1)/
	$(CP) ./scripts/collect_traffic.lua $(1)/usr/libexec/router_assistant/
	chmod 755 $(1)/usr/libexec/router_assistant/collect_traffic.lua
	$(CP) ./version.json $(1)/usr/share/router-assistant/
	$(CP) ./usr/lib/traffic_stats/* $(1)/usr/lib/traffic_stats/
	$(CP) ./usr/lib/json.lua $(1)/usr/lib/json/
	$(CP) ./etc/init.d/traffic-stats $(1)/etc/init.d/
	$(CP) ./usr/share/luci/menu.d/* $(1)/usr/share/luci/menu.d/

	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/traffic-stats $(1)/etc/rc.d/S95traffic-stats
endef

define Package/luci-app-router-assistant/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# 清除所有残留数据（确保重装时干净）
	for dir in /tmp/storage /mnt/mmcblk0p1 /mnt/sdcard /tmp; do
		[ -d "${dir}" ] || continue
		for subdir in router_assistant tmp/router_assistant; do
			if [ -d "${dir}/${subdir}" ]; then
				rm -f "${dir}/${subdir}/traffic_stats.json" \
				       "${dir}/${subdir}/traffic_monthly.json" \
				       "${dir}/${subdir}/traffic_hourly.json" \
				       "${dir}/${subdir}/mac_blocklist.json" \
				       "${dir}/${subdir}/blocked_macs_cache.json" 2>/dev/null
			fi
		done
	done
	rm -f /tmp/luci-indexcache
	/etc/init.d/traffic-stats enable 2>/dev/null
	/etc/init.d/traffic-stats start 2>/dev/null
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