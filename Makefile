#
# ATTENTION: Please check generated enum names before committing!
# See telio\ffi\bindings\windows\csharp\Telio.cs: Enum members need to be CamelCase, e.g.: AdapterBoringTun instead of TELIOADAPTERBORINGTUN.
#
# ATTENTION: Please use Arch Linux for generating the bindings!
# When using Ubuntu 20 or Debian 11.5, the resulting exports for Java and C# will deviate from what we expect and will create an incompatible API.
# Please see the Jira task for details on the reasons.
#
# Makefile version > 4.3 required

OSES := windows linux android darwin
LANGS := csharp go java

SWIG_linux := -D__unix__ -D__linux__
SWIG_android := -D__unix__ -D__ANDROID__
SWIG_darwin := -D__unix__ -D__APPLE__
SWIG_windows := -D_WIN32

FFI_DIR := ffi
BIND_DIR := $(FFI_DIR)/bindings
HELP_DIR := $(FFI_DIR)/helpers
CFG := $(BIND_DIR)/telio.i

GO_MODULE := teliogo

JAVA_PKG := com.nordsec.telio
JAVA_PATH := $(subst .,/,$(JAVA_PKG))

CS_NS := NordSec.Telio

PATH := $(PATH):$(HELP_DIR)

MIN_MAKE_VERSION := 4.3
all: check_version bindings

check_version:
	if [ `echo "$(MIN_MAKE_VERSION)>$(MAKE_VERSION)"|bc` -eq 1 ]; then \
        echo "Use Make version greater than $(MIN_MAKE_VERSION)"; \
		echo "You version is $(MAKE_VERSION)"; \
		exit 1; \
    fi

clean:
	rm -rf $(BIND_DIR)

headers:
	cbindgen -c cbindgen.toml -o $(FFI_DIR)/telio.h
	cbindgen -c cbindgen.toml -o $(FFI_DIR)/telio_types.h src/ffi/types.rs

binding_c:
	mkdir -p $(BIND_DIR)
	cbindgen -c cbindgen.toml -o $(BIND_DIR)/telio.h
	cbindgen -c cbindgen.toml -o $(BIND_DIR)/telio_types.h src/ffi/types.rs
	cp $(FFI_DIR)/*.i $(BIND_DIR)

define define_bindings
$(eval
	OS := $(1)
	SWIG := swig $(SWIG_$(OS))
	WD := $(BIND_DIR)/$(OS)/wrap
	GD := $(BIND_DIR)/$(OS)/go
	SD := $(BIND_DIR)/$(OS)/csharp
	JD := $(BIND_DIR)/$(OS)/java
)

base_$(OS): binding_c
	mkdir -p $(WD)
	cp $(HELP_DIR)/wrap/* $(WD)

binding_go_$(OS): base_$(OS)
	mkdir -p $(GD)
	$(SWIG) -go -module $(GO_MODULE) -intgosize 32 -cgo -outdir $(GD) -o $(WD)/go_wrap.c $(CFG)
	sed -i 's/^\(#include <stdint.h>\)$$$$/\1\n#include "callbacks.h"/' $(GD)/teliogo.go
	sed -i 's/type swig_gostring struct { p uintptr; n int }/type swig_gostring struct { p uintptr; n int32 }/' $(GD)/teliogo.go
	cp $(HELP_DIR)/go/* $(GD)
	# Generate list of exported functions
	./generate_wrap_exports.sh $(WD)/go_wrap

binding_csharp_$(OS): base_$(OS)
	mkdir -p $(SD)
	# Generate just c wrapper.
	$(SWIG) -csharp -namespace $(CS_NS) -outdir /dev -outfile null -o $(WD)/csharp_wrap.c $(CFG)
	# Generate just C# wrapper, since cscode works only in -c++ mode
	$(SWIG) -D_WIN32 -c++ -csharp -namespace $(CS_NS) -outdir $(SD) -outfile Telio.cs -o /dev/null $(CFG)
	sed -i 's/"libtelio"/"telio"/' $(SD)/Telio.cs
	# Generate list of exported functions
	./generate_wrap_exports.sh $(WD)/csharp_wrap

binding_java_$(OS): base_$(OS)
	mkdir -p $(JD)/$(JAVA_PATH)
	$(SWIG) -java -package $(JAVA_PKG) -outdir $(JD)/$(JAVA_PATH) -o $(WD)/java_wrap.c $(CFG)
	cp $(HELP_DIR)/java/* $(JD)/$(JAVA_PATH)
	sed -i 's/%JAVA_PKG%/$(JAVA_PKG)/' $(JD)/$(JAVA_PATH)/I*.java
	rm $(JD)/$(JAVA_PATH)/libtelio.java  #remove empty java class from artifacts
	# Generate list of exported functions
	./generate_wrap_exports.sh $(WD)/java_wrap

binding_$(OS): $(foreach L,$(LANGS),binding_$(L)_$(OS))

endef
$(foreach OS,$(OSES),$(eval $(call define_bindings,$(OS))))

bindings: clean $(foreach OS,$(OSES),binding_$(OS))

.PHONY: clean headers bindings

.EXPORT_ALL_VARIABLES:
