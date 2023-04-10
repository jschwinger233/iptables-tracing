# iptables-tracing

A tool to show iptables rules hit by specific traffic.

## Usage

To show a TCP SYN with speicfic source IPv4 and destination port:

```
sudo iptables-tracing 'src host 192.168.1.1 and dst port 80 and ip[20+13]&0x3f == 0x2'
```

For IPv6, please use `ip6tables-tracing` instead.

## Installation

Installation requires `libpcap`, which can be installed using `apt install libpcap-dev` for Ubuntu.

Then you can install from source:

```
git clone git@github.com:jschwinger233/iptables-tracing.git
cd iptables-tracing/
make build
sudo make install
```
