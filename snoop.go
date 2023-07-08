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

func iptablesSnoop(ctx context.Context, netns netns.NsHandle) (err error) {
	spec, err := loadIptablesSnoop()
	if err != nil {
		return
	}

	var s unix.Stat_t
	if err = unix.Fstat(int(netns), &s); err != nil {
		return
	}
	consts := map[string]interface{}{
		"CONFIG": uint32(s.Ino),
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

	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.SysEnterExecve, nil)
	if err != nil {
		return
	}
	defer kp.Close()

	for {
		event := iptablesSnoopEventT{}
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
		filename := string(event.Filename[:])
		if strings.Contains(filename, "iptables") || strings.Contains(filename, "ip6tables") {
			fmt.Printf("Warning: iptables might be modified by %s(%d)\n", filename, event.Pid)
		}
	}
	return
}
