sbin_PROGRAMS = cgdcbxd

cgdcbxd_SOURCES = cgdcbxd.c
cgdcbxd_LDADD = -lcgroup -lrt -lmnl

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wextra

## put a spec file and documentation in the distribution archive
dist_noinst_DATA = cgdcbxd.spec COPYING

## cgdcbxd.init is listed here because it gets installed from install-data-local
dist_noinst_SCRIPTS = cgdcbxd.init

## man pages
dist_man_MANS = cgdcbxd.8

## special hooks to handle the init script
install-data-local: cgdcbxd.init
	$(MKDIR_P) $(DESTDIR)/etc/init.d
	$(INSTALL_SCRIPT) cgdcbxd.init $(DESTDIR)/etc/init.d/cgdcbxd

install-data-hook:
	/sbin/chkconfig --add cgdcbxd || true

uninstall-local:
	/sbin/chkconfig --del cgdcbxd || true
	rm -f '$(DESTDIR)/etc/init.d/cgdcbxd'
