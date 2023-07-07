package main

import (
	"context"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	flag "github.com/spf13/pflag"
)

type Config struct {
	filter    string
	bin       string
	logPath   string
	rawOutput bool
}

var config Config

const (
	RED = "\033[0;31m"
	NC  = "\033[0m"
)

func init() {
	fmt.Println(RED + "# Warning: running this tool inside a container is likely to output nothing because it's supposed to read iptables logs from host" + NC)
	fmt.Println(RED + "# Warning: run \"sysctl -w net.netfilter.nf_log_all_netns=1\" to enable iptables logging for containers" + NC)

	flag.StringVarP(&config.bin, "bin", "b", "iptables", "iptables binary name; e.g. specify `ip6tables` for IPv6 tracing, or `iptables-lagecy` for legacy variant")
	flag.StringVarP(&config.logPath, "log", "l", "/var/log/syslog", "path to iptables log file")
	flag.BoolVarP(&config.rawOutput, "raw", "r", false, "output raw syslog lines")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lines, err := monitorLog(ctx, config.logPath)
	if err != nil {
		fmt.Printf("Error monitoring %s: %v\n", config.logPath, err)
		return
	}

	for line := range lines {
		originalIptables.Fprint(line, config.rawOutput)
	}

	// one more thing is to monitor the iptables modification events and give a warning
	// task -> netns, has to be the same
}
