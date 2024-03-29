package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native bpf bpf.c -- -I./headers

type Config struct {
	filter            string
	bin               string
	rawOutput         bool
	warnModification  bool
	blockModification bool
}

var config Config

const (
	RED = "\033[0;31m"
	NC  = "\033[0m"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(RED + "# Warning: run \"sysctl -w net.netfilter.nf_log_all_netns=1\" to enable iptables logging for containers" + NC)

	flag.StringVarP(&config.bin, "bin", "b", "iptables-nft", "iptables binary name; e.g. specify `ip6tables` for IPv6 tracing, or `iptables-lagecy` for legacy variant")
	flag.BoolVarP(&config.rawOutput, "raw", "r", false, "output raw syslog lines")
	flag.BoolVarP(&config.warnModification, "warn-modification", "w", false, "warn if iptables is modified")
	flag.BoolVarP(&config.blockModification, "block-modification", "B", false, "block iptables modification")
	flag.Parse()
	config.filter = strings.Join(flag.Args(), " ")
}

func main() {
	bpfCode, err := compileBPF(config.filter)
	if err != nil {
		fmt.Printf("Error compiling BPF \"%s\": %v\n", config.filter, err)
		return
	}

	iptables, err := iptablesSave()
	if err != nil {
		fmt.Printf("Error executing iptables-save: %+v\n", err)
		return
	}

	originalIptables := iptables.Copy()
	defer func() {
		if err := iptablesRestore(originalIptables); err != nil {
			fmt.Printf("Error restoring original iptables: %v\n", err)
			return
		}
	}()

	iptables.Insert(bpfCode)
	if err := iptablesRestore(iptables); err != nil {
		fmt.Printf("Error installing debug iptables: %v\n", err)
		return
	}

	objs, err := setupBpfObjects()
	if err != nil {
		fmt.Printf("Error setting up BPF objects: %v\n", err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if config.warnModification || config.blockModification {
		go func() {
			err := iptablesSnoop(ctx, objs)
			if err != nil {
				fmt.Printf("Error snooping iptables: %v\n", err)
				return
			}
		}()
	}

	lines, err := monitorLog(ctx, objs)
	if err != nil {
		fmt.Printf("Error monitoring %s: %v\n", err)
		return
	}

	fmt.Printf("Start tracing\n")
	for line := range lines {
		originalIptables.Fprint(line, config.rawOutput)
	}
}
