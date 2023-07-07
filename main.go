package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	flag "github.com/spf13/pflag"
)

type Config struct {
	filter string
	bin    string
}

var config Config

func init() {
	flag.StringVarP(&config.bin, "bin", "b", "iptables", "iptables binary name; e.g. specify `ip6tables` for IPv6 tracing, or `iptables-lagecy` for legacy variant")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()

	// monitor log and parse output

	// one more thing is to monitor the iptables modification events and give a warning
}
