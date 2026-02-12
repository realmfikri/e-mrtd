SHELL := /bin/bash

# Java Card build settings (override via environment if needed)
PACKAGE_NAME ?= cardapplet
APPLET_CLASS ?= EducationalEmrtdApplet
PACKAGE_AID ?= 0xA0:0x00:0x00:0x02:0x47:0x10:0x00
APPLET_AID ?= 0xA0:0x00:0x00:0x02:0x47:0x10:0x00:0x01
APPLET_VERSION ?= 1.0
JAVAC_RELEASE ?= 8

SRC_DIR := applet-src
BUILD_DIR := build
CLASS_DIR := $(BUILD_DIR)/classes
CAP_TMP := $(BUILD_DIR)/$(PACKAGE_NAME)/javacard/$(PACKAGE_NAME).cap
CAP_OUT := $(BUILD_DIR)/applet.cap

SAMPLE_DIR := sample-data
SAMPLE_EF_COM := $(SAMPLE_DIR)/EF_COM.bin
SAMPLE_DG1 := $(SAMPLE_DIR)/DG1.bin

JAVAC := $(JAVA_HOME)/bin/javac
JAVA := $(JAVA_HOME)/bin/java
UNZIP ?= unzip

# JCKIT compatibility:
# - "classic SDK" layout (older): lib/api.jar + lib/converter.jar + api_export_files/
# - "tools-only" layout (newer): lib/api_classic-*.jar + bin/converter.sh + lib/tools.jar (exports embedded)
JC_TOOLS_JAR := $(JCKIT)/lib/tools.jar
JC_CONVERTER_SH := $(JCKIT)/bin/converter.sh

# Auto-detect platform target for tools-only kits (used for export extraction + converter -target).
# Override with environment: `make JC_TARGET=3.0.5 ...`
JC_TARGET_AUTO := $(shell \
	ls -1 "$(JCKIT)"/lib/api_classic-*.jar 2>/dev/null | \
	sort -V | tail -n1 | \
	sed 's#.*/api_classic-##; s#.jar$$##' \
)
JC_TARGET ?= $(JC_TARGET_AUTO)

# Pick the API jar available in the kit.
# Prefer classic api.jar, otherwise pick api_classic-<JC_TARGET>.jar (if available), otherwise newest api_classic-*.jar.
JC_API := $(shell \
	if [ -f "$(JCKIT)/lib/api.jar" ]; then \
		echo "$(JCKIT)/lib/api.jar"; \
	elif [ -n "$(JC_TARGET)" ] && [ -f "$(JCKIT)/lib/api_classic-$(JC_TARGET).jar" ]; then \
		echo "$(JCKIT)/lib/api_classic-$(JC_TARGET).jar"; \
	else \
		ls -1 "$(JCKIT)"/lib/api_classic-*.jar 2>/dev/null | sort -V | tail -n1; \
	fi \
)

JC_CONVERTER_CP := $(JCKIT)/lib/converter.jar:$(JCKIT)/lib/offcardverifier.jar
JC_EXPORTS := $(JCKIT)/api_export_files
JC_EXPORTS_FALLBACK_ROOT := $(BUILD_DIR)/jckit_exports
JC_EXPORTS_FALLBACK := $(JC_EXPORTS_FALLBACK_ROOT)/api_export_files_$(JC_TARGET)
JC_EXPORTS_DIR := $(shell if [ -d "$(JC_EXPORTS)" ]; then echo "$(JC_EXPORTS)"; else echo "$(JC_EXPORTS_FALLBACK)"; fi)
JC_CONVERTER_TARGET_OPT := $(if $(JC_TARGET),-target $(JC_TARGET),)

.PHONY: all clean check-env compile cap prepare-sample-data prepare-jckit-exports

all: prepare-sample-data $(CAP_OUT)

check-env:
	@test -n "$(JAVA_HOME)" || { echo "ERROR: JAVA_HOME must be set"; exit 1; }
	@test -n "$(JCKIT)" || { echo "ERROR: JCKIT must be set"; exit 1; }
	@test -x "$(JAVAC)" || { echo "ERROR: javac not found at $(JAVAC)"; exit 1; }
	@test -x "$(JAVA)" || { echo "ERROR: java not found at $(JAVA)"; exit 1; }
	@test -n "$(JC_API)" || { echo "ERROR: unable to find Java Card API jar under $(JCKIT)/lib (expected api.jar or api_classic-*.jar)"; exit 1; }
	@test -f "$(JC_API)" || { echo "ERROR: Java Card API jar not found at $(JC_API)"; exit 1; }
	@if [ -x "$(JC_CONVERTER_SH)" ]; then \
		:; \
	elif [ -f "$(JCKIT)/lib/converter.jar" ]; then \
		:; \
	else \
		echo "ERROR: converter not found. Expected $(JC_CONVERTER_SH) (tools-only kits) OR $(JCKIT)/lib/converter.jar (classic SDK)."; \
		exit 1; \
	fi
	@if [ -d "$(JC_EXPORTS)" ]; then \
		:; \
	elif [ -f "$(JC_TOOLS_JAR)" ]; then \
		command -v "$(UNZIP)" >/dev/null 2>&1 || { echo "ERROR: $(UNZIP) not found (needed to extract export files from tools.jar)"; exit 1; }; \
		test -n "$(JC_TARGET)" || { echo "ERROR: could not derive JC_TARGET from $(JC_API). Set JC_TARGET (e.g. 3.2.0) or use a kit with api_export_files/."; exit 1; }; \
	else \
		echo "ERROR: api_export_files not found at $(JC_EXPORTS) and no tools.jar available at $(JC_TOOLS_JAR) for fallback exports."; \
		exit 1; \
	fi

prepare-sample-data:
	@mkdir -p "$(SAMPLE_DIR)"
	@if [ ! -f "$(SAMPLE_EF_COM)" ]; then \
		printf 'TEST ONLY EF_COM\nFICTIONAL DEMO LDS\n' > "$(SAMPLE_EF_COM)"; \
		echo "Generated synthetic $(SAMPLE_EF_COM)"; \
	fi
	@if [ ! -f "$(SAMPLE_DG1)" ]; then \
		printf 'TEST ONLY DG1\nFICTIONAL HOLDER: DOE<<ALEX\n' > "$(SAMPLE_DG1)"; \
		echo "Generated synthetic $(SAMPLE_DG1)"; \
	fi

$(CLASS_DIR):
	@mkdir -p "$(CLASS_DIR)"

compile: check-env | $(CLASS_DIR)
	$(JAVAC) \
		--release "$(JAVAC_RELEASE)" \
		-classpath "$(JC_API):$(SRC_DIR)" \
		-d "$(CLASS_DIR)" \
		-sourcepath "$(SRC_DIR)" \
		$(SRC_DIR)/*.java

prepare-jckit-exports: check-env
	@if [ -d "$(JC_EXPORTS)" ]; then \
		echo "Using Java Card export files from: $(JC_EXPORTS)"; \
	else \
		echo "Extracting Java Card export files from tools.jar (target $(JC_TARGET)) -> $(JC_EXPORTS_FALLBACK)"; \
		mkdir -p "$(JC_EXPORTS_FALLBACK_ROOT)"; \
		"$(UNZIP)" -q -o "$(JC_TOOLS_JAR)" "api_export_files_$(JC_TARGET)/*" -d "$(JC_EXPORTS_FALLBACK_ROOT)"; \
		test -d "$(JC_EXPORTS_FALLBACK)" || { echo "ERROR: extracted export files missing at $(JC_EXPORTS_FALLBACK)"; exit 1; }; \
	fi

cap: compile prepare-jckit-exports
ifneq (,$(wildcard $(JC_CONVERTER_SH)))
	"$(JC_CONVERTER_SH)" \
		$(JC_CONVERTER_TARGET_OPT) \
		-classdir "$(CLASS_DIR)" \
		-exportpath "$(JC_EXPORTS_DIR)" \
		-applet "$(APPLET_AID)" "$(PACKAGE_NAME).$(APPLET_CLASS)" \
		-d "$(BUILD_DIR)" \
		-out CAP \
		-v \
		"$(PACKAGE_NAME)" "$(PACKAGE_AID)" "$(APPLET_VERSION)"
else
	$(JAVA) \
		-classpath "$(JC_CONVERTER_CP)" \
		com.sun.javacard.converter.Converter \
		-classdir "$(CLASS_DIR)" \
		-exportpath "$(JC_EXPORTS_DIR)" \
		-applet "$(APPLET_AID)" "$(PACKAGE_NAME).$(APPLET_CLASS)" \
		-d "$(BUILD_DIR)" \
		-out CAP \
		-v \
		"$(PACKAGE_NAME)" "$(PACKAGE_AID)" "$(APPLET_VERSION)"
endif

$(CAP_OUT): cap
	@cp "$(CAP_TMP)" "$(CAP_OUT)"
	@echo "CAP created at $(CAP_OUT)"

clean:
	rm -rf "$(BUILD_DIR)"
