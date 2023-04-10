# iptables-tracing

A tool to show iptables rules hit by specific traffic.

## Usage

To show a TCP SYN with speicfic source IPv4 and destination port:

```
sudo iptables-tracing 'src host 192.168.1.1 and dst port 80 and ip[20+13]&0x3f == 0x2'
```

## Installation

```
git clone git@github.com:jschwinger233/iptables-tracing.git
make
sudo make install
```
