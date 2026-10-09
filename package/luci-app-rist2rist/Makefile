include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-rist2rist
PKG_VERSION:=1.0.0
PKG_RELEASE:=38
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
  # +umdns is a real dependency, not a nicety: the bridge advertises itself over
  # mDNS so the encoder's Find can discover it, and a missing umdns used to fail
  # silently -- the bridge looked healthy, advertised nothing, and Find found no
  # bridge at all.
  DEPENDS:=+libopenssl +cJSON +luci-base +umdns
endef

# Step 1: materialise the source. ./src is PRISTINE upstream librist (pinned at the commit
# named in patches/README) and every open-broadcast change lives in ./patches, so the
# customisation is reviewable here in the app repo and survives a clean clone.
# (Previously the edits were made in-place in ./src, which was also an embedded git repo —
# so nothing was tracked by this repo and a clean checkout could not build at all.)
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(Build/Patch)
endef

# Build only the two binaries this package SHIPS; ninja's dep graph stops at
# librist.a + its objects, so ristsender/ristreceiver/udp2udp/risttunnel/
# ristsrppasswd never link.
define Build/Compile
	$(call Build/Compile/Meson,tools/rist2rist tools/rist2rist-probe)
endef

# Bypass the default `ninja install` (which would re-link every tool with install: true).
# Stage just the two binaries into $(PKG_INSTALL_DIR) for Package/install to consume.
define Build/Install
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/usr/bin
	$(INSTALL_BIN) $(MESON_BUILD_DIR)/tools/rist2rist $(PKG_INSTALL_DIR)/usr/bin/rist2rist
	$(INSTALL_BIN) $(MESON_BUILD_DIR)/tools/rist2rist-probe $(PKG_INSTALL_DIR)/usr/bin/rist2rist-probe
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


	# ifup hook: a WAN leg skipped while its modem was absent is rebuilt when
	# the interface appears, so an unplugged modem is a non-event rather than
	# something an operator has to notice and fix by hand.
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/99-rist2rist $(1)/etc/hotplug.d/iface/99-rist2rist
	# rpcd exec plugin: the bridge API (milestone M-B1) that the encoder calls as
	# JSON-RPC over HTTP at /ubus. LuCI remains another client of the same
	# methods, so there is one API rather than two.
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/rist2rist $(1)/usr/libexec/rpcd/rist2rist

	# Passive per-WAN measurement snapshot: a one-shot admin tool. It only reads
	# (sysfs, tc, mmcli, uci) -- it is never a service. /usr/sbin matches the sbin
	# convention for admin tools.
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/rist2rist-measure $(1)/usr/sbin/rist2rist-measure

	# The ACTIVE per-leg probe: the other half of the measurement, and the
	# instrument the modem WAN test is run with. It puts traffic on the link, so
	# it is an operator-invoked sbin tool and never a service -- it refuses to run
	# while a session is up. Installed from the meson build, beside rist2rist.
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/rist2rist-probe $(1)/usr/sbin/rist2rist-probe

	# Shared WAN-link resolver (DT-27.3): ONE definition of "this box's WAN links",
	# SOURCED by both the init (to bind the output leg) and the measurement helper
	# (to enumerate legs). Not executable -- it is sourced, so plain data mode.
	$(INSTALL_DIR) $(1)/usr/lib/rist2rist
	$(INSTALL_DATA) ./files/rist2rist-wan.sh $(1)/usr/lib/rist2rist/wan.sh

	# The HTTP face of that same API. LuCI's uhttpd cannot serve it (its ubus
	# plugin denies every call on this image) and uhttpd's -a would expose every
	# ubus object on the LAN to reach this one, so the endpoint gets its own
	# docroot holding exactly one file -- a shim narrowed to rist2rist -- and its
	# own procd service, so it survives an upgrade instead of being a hand-run
	# listener.
	$(INSTALL_DIR) $(1)/www-bridge
	$(INSTALL_BIN) ./files/www-bridge/ubus $(1)/www-bridge/ubus
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/obr-bridge-api.init $(1)/etc/init.d/obr-bridge-api
endef

define Package/luci-app-rist2rist/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/rpcd restart 2>/dev/null || true
/etc/init.d/uhttpd reload 2>/dev/null || true
# The control endpoint must be ENABLED, not merely installed: without this the
# advertised api_port would name a port nothing listens on.
/etc/init.d/obr-bridge-api enable 2>/dev/null || true
/etc/init.d/obr-bridge-api restart 2>/dev/null || true
# An upgrade restarts rpcd/uhttpd but would leave the RELAY itself stopped, so a
# box that was relaying comes back up silent. Restart it if it is enabled.
if /etc/init.d/rist2rist enabled 2>/dev/null; then
	/etc/init.d/rist2rist restart 2>/dev/null || true
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-rist2rist))