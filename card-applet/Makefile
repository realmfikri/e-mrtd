SHELL := /bin/bash

# Java Card build settings (override via environment if needed)
PACKAGE_NAME ?= cardapplet
APPLET_CLASS ?= EducationalEmrtdApplet
PACKAGE_AID ?= 0xA0:0x00:0x00:0x02:0x47:0x10:0x00
APPLET_AID ?= 0xA0:0x00:0x00:0x02:0x47:0x10:0x00:0x01
APPLET_VERSION ?= 1.0

SRC_DIR := applet-src
BUILD_DIR := build
CLASS_DIR := $(BUILD_DIR)/classes
CAP_TMP := $(BUILD_DIR)/$(PACKAGE_NAME)/javacard/$(PACKAGE_NAME).cap
CAP_OUT := $(BUILD_DIR)/applet.cap

JAVAC := $(JAVA_HOME)/bin/javac
JAVA := $(JAVA_HOME)/bin/java
JC_API := $(JCPATH)/lib/api.jar
JC_CONVERTER_CP := $(JCPATH)/lib/converter.jar:$(JCPATH)/lib/offcardverifier.jar
JC_EXPORTS := $(JCPATH)/api_export_files

.PHONY: all clean check-env compile cap

all: $(CAP_OUT)

check-env:
	@test -n "$(JAVA_HOME)" || { echo "ERROR: JAVA_HOME must be set"; exit 1; }
	@test -n "$(JCPATH)" || { echo "ERROR: JCPATH must be set"; exit 1; }
	@test -x "$(JAVAC)" || { echo "ERROR: javac not found at $(JAVAC)"; exit 1; }
	@test -x "$(JAVA)" || { echo "ERROR: java not found at $(JAVA)"; exit 1; }
	@test -f "$(JC_API)" || { echo "ERROR: Java Card api.jar not found at $(JC_API)"; exit 1; }
	@test -f "$(JCPATH)/lib/converter.jar" || { echo "ERROR: converter.jar not found at $(JCPATH)/lib/converter.jar"; exit 1; }
	@test -d "$(JC_EXPORTS)" || { echo "ERROR: api_export_files not found at $(JC_EXPORTS)"; exit 1; }

$(CLASS_DIR):
	@mkdir -p "$(CLASS_DIR)"

compile: check-env | $(CLASS_DIR)
	$(JAVAC) \
		-classpath "$(JC_API):$(SRC_DIR)" \
		-d "$(CLASS_DIR)" \
		-sourcepath "$(SRC_DIR)" \
		$(SRC_DIR)/*.java

cap: compile
	$(JAVA) \
		-classpath "$(JC_CONVERTER_CP)" \
		com.sun.javacard.converter.Converter \
		-classdir "$(CLASS_DIR)" \
		-exportpath "$(JC_EXPORTS)" \
		-applet "$(APPLET_AID)" "$(PACKAGE_NAME).$(APPLET_CLASS)" \
		-d "$(BUILD_DIR)" \
		-out CAP \
		-v \
		"$(PACKAGE_NAME)" "$(PACKAGE_AID)" "$(APPLET_VERSION)"

$(CAP_OUT): cap
	@cp "$(CAP_TMP)" "$(CAP_OUT)"
	@echo "CAP created at $(CAP_OUT)"

clean:
	rm -rf "$(BUILD_DIR)"
