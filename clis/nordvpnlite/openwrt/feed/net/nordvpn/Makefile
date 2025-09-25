include $(TOPDIR)/rules.mk

PKG_NAME:=nordvpn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=NordSecurity
PKG_LICENSE:=GPLv3

include $(INCLUDE_DIR)/package.mk

define Package/nordvpn
	SECTION:=net
	CATEGORY:=Network
	TITLE:=NordVPN
	DEPENDS:=+kmod-tun +kmod-wireguard
	URL:=https://www.nordsecurity.com
endef

define Package/nordvpn/description
	NordVPN is the gateway to a secure and private access to the internet.
endef

define Build/Compile
	# nothing to do
endef

define Package/nordvpn/install
	@if [ -z "$(PKG_BINFILE)" ]; then \
		echo "ERROR: PKG_BINFILE is empty!" >&2; \
		exit 1; \
	elif [ ! -f "$(PKG_BINFILE)" ]; then \
		echo "ERROR: \"${PKG_BINFILE}\" pointed by PKG_BINFILE does not exist!" >&2; \
		exit 1; \
	fi
	@echo "Using prebuilt nordvpnlite: ${PKG_BINFILE}"

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ${PKG_BINFILE} $(1)/usr/sbin/nordvpn

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nordvpn.init $(1)/etc/init.d/nordvpn
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/nordvpn.conf $(1)/etc/config/nordvpn
	$(INSTALL_DIR) $(1)/etc/nordvpn
	$(INSTALL_DATA) ./files/config.json $(1)/etc/nordvpn/config.json
endef

$(eval $(call BuildPackage,nordvpn))
