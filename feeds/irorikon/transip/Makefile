include $(TOPDIR)/rules.mk

PKG_NAME:=transip
PKG_RELEASE:=1.0.0

include $(INCLUDE_DIR)/package.mk

define Package/transip/default
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=transip
	TITLE:=transip
	VERSION:=$(PKG_RELEASE)
endef

define Package/transip
  $(Package/transip/default)
endef

define Package/transip/description
	transip openwrt plugin
endef

define Package/transip/conffiles
	/etc/transip/transip.conf
$(call $(TARGET)/conffiles)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef
define Build/Compile/Default
endef
Build/Compile = $(Build/Compile/Default)

define Package/transip/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/transip.init $(1)/etc/init.d/transip
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/arm64/tun2socks $(1)/usr/bin/tun2socks
	$(INSTALL_BIN) ./files/arm64/transip $(1)/usr/bin/transip
	$(INSTALL_BIN) ./files/arm64/transip_bind $(1)/usr/bin/transip_bind
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_CONF) ./files/transip.config $(1)/etc/config/transip
endef

$(eval $(call BuildPackage,transip))