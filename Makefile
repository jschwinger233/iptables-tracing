.PHONY: install

INSTALL_DIR := /usr/local/bin

EXECUTABLE_IPV4 := iptables-tracing
EXECUTABLE_IPV6 := ip6tables-tracing

SOURCE_PATH := iptables-tracing
DESTINATION_IPV4 := $(INSTALL_DIR)/$(EXECUTABLE_IPV4)
DESTINATION_IPV6 := $(INSTALL_DIR)/$(EXECUTABLE_IPV6)

install:
	cp $(SOURCE_PATH) $(DESTINATION_IPV4)
	cp $(SOURCE_PATH) $(DESTINATION_IPV6)