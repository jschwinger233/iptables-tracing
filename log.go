package main

import (
	"context"
	"time"

	"github.com/cilium/ebpf/link"
)

func monitorLog(ctx context.Context, objs *bpfObjects) (_ <-chan string, err error) {
	kp, err := link.Kprobe("nf_log_buf_close", objs.NfLogBufClose, nil)
	if err != nil {
		return
	}

	ch := make(chan string)
	go func() {
		defer kp.Close()
		defer close(ch)

		for {
			event := bpfNfLogEvent{}
			for {
				if err := objs.NfLogEvents.LookupAndDelete(nil, &event); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Microsecond):
					continue
				}
			}
			ch <- string(event.Buf[2:])
		}
	}()
	return ch, nil
}
