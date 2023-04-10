.PHONY: build install

INSTALL_DIR := /usr/local/bin

build:
	curl https://git.netfilter.org/iptables/plain/utils/nfbpf_compile.c -OL
	gcc -I/usr/include/pcap nfbpf_compile.c -lpcap -o nfbpf_compile

install:
	cp nfbpf_compile $(INSTALL_DIR)/
	cp iptables-tracing $(INSTALL_DIR)/iptables-tracing
	cp iptables-tracing $(INSTALL_DIR)/ip6tables-tracing
