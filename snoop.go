package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
)

type bpfConfig struct {
	netns uint32
	block uint8
	pads  [3]uint8
}

func iptablesSnoop(ctx context.Context, objs *bpfObjects) (err error) {
	kp, err := link.Kprobe("sys_execve", objs.SysExecve, nil)
	if err != nil {
		return
	}
	defer kp.Close()

	for {
		event := bpfExecEvent{}
		for {
			if err := objs.ExecEvents.LookupAndDelete(nil, &event); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}
		cmd := []string{}
		for _, arg := range event.Args {
			cmd = append(cmd, string(arg[:]))
		}
		if config.blockModification {
			fmt.Printf(RED+"Warning: iptables operation was blocked: %d(%s)\n"+NC, event.Pid, strings.Trim(strings.Join(cmd, " "), string([]byte{0, ' '})))
		} else {
			fmt.Printf(RED+"Warning: iptables might be modified by %d(%s)\n"+NC, event.Pid, strings.Trim(strings.Join(cmd, " "), string([]byte{0, ' '})))
		}
	}
	return
}
