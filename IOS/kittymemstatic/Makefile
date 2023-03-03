FINALPACKAGE := 1
TARGET := iphone:clang:latest:12.2
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = kittymemstatic

$(LIBRARY_NAME)_FILES = $(wildcard *.mm)
$(LIBRARY_NAME)_CFLAGS = -fobjc-arc -w
$(LIBRARY_NAME)_INSTALL_PATH = /usr/local/lib
$(LIBRARY_NAME)_LINKAGE_TYPE = static

include $(THEOS_MAKE_PATH)/library.mk
