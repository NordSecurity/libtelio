include $(TOPDIR)/rules.mk

PKG_NAME:=nordvpnlite
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=NordSecurity
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE THIRD-PARTY-NOTICES

include $(INCLUDE_DIR)/package.mk

define Package/nordvpnlite
	SECTION:=net
	CATEGORY:=Network
	TITLE:=NordVPN Lite
	DEPENDS:=+kmod-tun +kmod-wireguard
	URL:=https://www.nordsecurity.com
endef

define Package/nordvpnlite/description
	NordVPN Lite is the gateway to a secure and private access to the internet.
endef

define Build/Compile
	# nothing to do
endef

define Package/nordvpnlite/install
	@if [ -z "$(PKG_BINFILE)" ]; then \
		echo "ERROR: PKG_BINFILE is empty!" >&2; \
		exit 1; \
	elif [ ! -f "$(PKG_BINFILE)" ]; then \
		echo "ERROR: \"${PKG_BINFILE}\" pointed by PKG_BINFILE does not exist!" >&2; \
		exit 1; \
	fi
	@echo "Using prebuilt nordvpnlite: ${PKG_BINFILE}"

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ${PKG_BINFILE} $(1)/usr/sbin/nordvpnlite

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nordvpnlite.init $(1)/etc/init.d/nordvpnlite
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/nordvpnlite.conf $(1)/etc/config/nordvpnlite
	$(INSTALL_DIR) $(1)/etc/nordvpnlite
	$(INSTALL_DATA) ./files/config.json $(1)/etc/nordvpnlite/config.json
endef

$(eval $(call BuildPackage,nordvpnlite))
