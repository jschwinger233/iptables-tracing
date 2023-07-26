package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type bpfConfig struct {
	netns uint32
	block uint8
	pads  [3]uint8
}

func iptablesSnoop(ctx context.Context, netns netns.NsHandle) (err error) {
	spec, err := loadIptablesSnoop()
	if err != nil {
		return
	}

	var s unix.Stat_t
	if err = unix.Fstat(int(netns), &s); err != nil {
		return
	}

	block := uint8(0)
	if config.blockModification {
		block = 1
	}
	consts := map[string]interface{}{
		"CONFIG": bpfConfig{
			netns: uint32(s.Ino),
			block: block,
		},
	}
	if err = spec.RewriteConstants(consts); err != nil {
		return
	}

	objs := &iptablesSnoopObjects{}
	if err = spec.LoadAndAssign(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			err = fmt.Errorf("%+v: %+v\n", err, ve)
		}
		return
	}

	kp, err := link.Kprobe("sys_execve", objs.SysExecve, nil)
	if err != nil {
		return
	}
	defer kp.Close()

	for {
		event := iptablesSnoopEvent{}
		for {
			if err := objs.Events.LookupAndDelete(nil, &event); err == nil {
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
