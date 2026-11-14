# Build and install the C library (Linux, macOS, BSD; Windows: see README).
#
#   make                                 build shared and static libraries
#   sudo make install                    install library, header, pkg-config
#                                        file and CMake package
#   sudo make uninstall
#
# PREFIX (default /usr/local), LIBDIR, INCLUDEDIR and DESTDIR are honoured,
# as are CARGO and CARGO_FLAGS (e.g. CARGO_FLAGS=--offline). On macOS the
# install path is built into the library, so pass the same PREFIX/LIBDIR
# to `make` and `make install`.
#
# `make` always runs Cargo, which knows what is up to date, including
# Cargo.lock and a smpte-klv checkout patched in through .cargo/config.toml.
# `make install` on its own builds only when a library is missing or older
# than Cargo.toml, Cargo.lock or src/, so `sudo make install` after `make`
# installs what `make` built without running Cargo as root.

PREFIX      ?= /usr/local
LIBDIR      ?= $(PREFIX)/lib
INCLUDEDIR  ?= $(PREFIX)/include
DESTDIR     ?=
CARGO       ?= cargo
CARGO_FLAGS ?=
PROFILE     ?= release
TARGET_DIR  ?= target/c

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
ABI     := $(shell sed -n 's/^\#define MISB_ABI_VERSION \([0-9][0-9]*\).*/\1/p' include/misb.h)
OUT     := $(TARGET_DIR)/$(if $(filter dev,$(PROFILE)),debug,$(PROFILE))
SOURCES := Cargo.toml $(wildcard Cargo.lock) $(shell find src -name '*.rs')
# FORCE when the goals include `all` (or there are none): see above.
REBUILD := $(if $(filter all,$(or $(MAKECMDGOALS),all)),FORCE)

ifeq ($(shell uname -s),Darwin)
  BUILT_SHARED := libmisb.dylib
  SHARED       := libmisb.$(ABI).dylib
  LINK_NAME    := libmisb.dylib
  SONAME_ARG   := -Wl,-install_name,$(LIBDIR)/$(SHARED)
else
  BUILT_SHARED := libmisb.so
  SHARED       := libmisb.so.$(ABI)
  LINK_NAME    := libmisb.so
  SONAME_ARG   := -Wl,-soname,$(SHARED)
endif

SHARED_LIB := $(OUT)/$(BUILT_SHARED)
STATIC_LIB := $(OUT)/libmisb.a
# The system libraries the static library needs, as rustc reports them.
NATIVE     := $(OUT)/native-static-libs
CMAKE_DIR  := $(LIBDIR)/cmake/misb

SUBST = sed -e 's|@VERSION@|$(VERSION)|g' -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@LIBDIR@|$(LIBDIR)|g' \
	-e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' -e 's|@SHARED@|$(SHARED)|g' \
	-e "s|@NATIVE_LIBS@|$$(cat $(NATIVE))|g" \
	-e "s|@NATIVE_LIBS_CMAKE@|$$(sed -e 's/-framework /-framework@/g' -e 's/ /;/g' -e 's/@/ /g' $(NATIVE))|g"

.PHONY: all install uninstall clean FORCE

all: $(SHARED_LIB) $(STATIC_LIB)

# Cargo may leave an up-to-date file untouched, hence the touch.
$(SHARED_LIB): $(SOURCES) $(REBUILD)
	@test -n "$(VERSION)" -a -n "$(ABI)" || { echo "cannot read the version from Cargo.toml and include/misb.h"; exit 1; }
	$(CARGO) rustc --color never $(CARGO_FLAGS) --lib --profile $(PROFILE) --crate-type cdylib --target-dir $(TARGET_DIR) \
		-- -C link-arg=$(SONAME_ARG) -C strip=symbols
	@touch $@

$(STATIC_LIB): $(SOURCES) $(REBUILD)
	@mkdir -p $(OUT)
	$(CARGO) rustc --color never $(CARGO_FLAGS) --lib --profile $(PROFILE) --crate-type staticlib --target-dir $(TARGET_DIR) \
		-- --print native-static-libs 2> $(OUT)/staticlib.log || { cat $(OUT)/staticlib.log; exit 1; }
	@sed -n 's/^note: native-static-libs: //p' $(OUT)/staticlib.log | tail -n 1 > $(NATIVE)
	@test -s $(NATIVE) || { echo "rustc did not report the static library's system libraries"; exit 1; }
	@touch $@

install: all
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR)/pkgconfig $(DESTDIR)$(CMAKE_DIR)
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/$(SHARED)
	ln -sf $(SHARED) $(DESTDIR)$(LIBDIR)/$(LINK_NAME)
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/libmisb.a
	install -m 644 include/misb.h $(DESTDIR)$(INCLUDEDIR)/misb.h
	@echo "generating $(DESTDIR)$(LIBDIR)/pkgconfig/misb.pc and $(DESTDIR)$(CMAKE_DIR)/*.cmake"
	@$(SUBST) c/misb.pc.in > $(DESTDIR)$(LIBDIR)/pkgconfig/misb.pc
	@$(SUBST) c/misb-config.cmake.in > $(DESTDIR)$(CMAKE_DIR)/misb-config.cmake
	@$(SUBST) c/misb-config-version.cmake.in > $(DESTDIR)$(CMAKE_DIR)/misb-config-version.cmake

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED) $(DESTDIR)$(LIBDIR)/$(LINK_NAME) $(DESTDIR)$(LIBDIR)/libmisb.a
	rm -f $(DESTDIR)$(INCLUDEDIR)/misb.h $(DESTDIR)$(LIBDIR)/pkgconfig/misb.pc
	rm -f $(DESTDIR)$(CMAKE_DIR)/misb-config.cmake $(DESTDIR)$(CMAKE_DIR)/misb-config-version.cmake
	-rmdir $(DESTDIR)$(CMAKE_DIR) 2>/dev/null

clean:
	rm -rf $(TARGET_DIR)

FORCE:
