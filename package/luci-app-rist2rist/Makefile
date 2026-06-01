include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-rist2rist
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/meson.mk

# Meson flags. Must use MESON_ARGS+=, not a positional arg to Build/Configure/Meson —
# the wrapper in include/meson.mk hardcodes its setup command and ignores extra args.
# - default_library=static: link librist.a directly into rist2rist (no .so dep)
# - test=false:             skip the test subdir
# - built_tools=true:       (default) keep tools subdir so tools/rist2rist exists
# - builtin_mbedtls=true:   force the bundled mbedtls. Without this, contrib/mbedtls/meson.build
#                           runs `dependency('MbedTLS', method: 'cmake', ...)` which finds the
#                           *host* mbedtls (if installed) and bleeds -I/usr/include into every
#                           compile, breaking the cross build.
MESON_ARGS+=-Ddefault_library=static -Dtest=false -Dbuilt_tools=true -Dbuiltin_mbedtls=true

define Package/luci-app-rist2rist
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for Custom Reactive RIST Proxy
  DEPENDS:=+libopenssl +cJSON +luci-base
endef

# Step 1: Copy your local development src folder straight into the compilation workspace
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

# Build only tools/rist2rist; ninja's dep graph stops at librist.a + its objects,
# so ristsender/ristreceiver/udp2udp/risttunnel/ristsrppasswd never link.
define Build/Compile
	$(call Build/Compile/Meson,tools/rist2rist)
endef

# Bypass the default `ninja install` (which would re-link every tool with install: true).
# Stage just the one binary into $(PKG_INSTALL_DIR) for Package/install to consume.
define Build/Install
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/usr/bin
	$(INSTALL_BIN) $(MESON_BUILD_DIR)/tools/rist2rist $(PKG_INSTALL_DIR)/usr/bin/rist2rist
endef

define Package/luci-app-rist2rist/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/rist2rist $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/rist2rist.config $(1)/etc/config/rist2rist

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/rist2rist.init $(1)/etc/init.d/rist2rist

	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/rist2rist.js $(1)/www/luci-static/resources/view/

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-rist2rist.json $(1)/usr/share/luci/menu.d/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-rist2rist.json $(1)/usr/share/rpcd/acl.d/
endef

define Package/luci-app-rist2rist/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/rpcd restart 2>/dev/null || true
/etc/init.d/uhttpd reload 2>/dev/null || true
exit 0
endef

$(eval $(call BuildPackage,luci-app-rist2rist))