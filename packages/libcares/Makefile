include $(TOPDIR)/rules.mk

PKG_NAME:=libcares
PKG_VERSION:=1.34.6
PKG_RELEASE:=1

PKG_SOURCE:=c-ares-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/c-ares/c-ares/releases/download/cares-$(PKG_VERSION)/
PKG_HASH:=skip

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE.md
PKG_MAINTAINER:=RouterAssistant

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libcares
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Asynchronous DNS resolver library (C library)
  URL:=https://c-ares.org/
  DEPENDS:=+libc
  PKGARCH:=aarch64_cortex-a53
endef

define Package/libcares/description
 c-ares is a C library for asynchronous DNS requests.
 
 This package provides version 1.34.6 which is required by https-dns-proxy
 for DNS over HTTPS (DoH) support on ARM64 routers.
endef

define Package/libcares/config
menu "Configuration"
    depends on PACKAGE_libcares
    
    config LIBCARES_STATIC
        bool "Build static library"
        default n
        
    config LIBCARES_DEBUG
        bool "Enable debug output"
        default n
endmenu
endef

TARGET_CFLAGS += $(FPIC)

CONFIGURE_ARGS += \
	--enable-shared \
	--enable-static=$(if $(CONFIG_LIBCARES_STATIC),yes,no) \
	--disable-tests \
	--disable-examples-docs \
	--without-random \
	$(if $(CONFIG_LIBCARES_DEBUG),--enable-debug,--disable-debug)

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/*.h $(1)/usr/include/
	
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcares*.{a,la,so*} $(1)/usr/lib/
endef

define Package/libcares/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcares*.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libcares))
