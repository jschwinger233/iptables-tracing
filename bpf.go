package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

func compileBPF(expr string) (code string, err error) {
	if len(expr) == 0 {
		return "", errors.New("empty filter")
	}

	pcap := C.pcap_open_dead(C.DLT_RAW, MAXIMUM_SNAPLEN)
	if pcap == nil {
		return "", fmt.Errorf("failed to pcap_open_dead: %+v\n", C.PCAP_ERROR)
	}
	defer C.pcap_close(pcap)

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpfProg pcapBpfProgram
	if C.pcap_compile(pcap, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return "", fmt.Errorf("failed to pcap_compile '%s': %+v", expr, C.GoString(C.pcap_geterr(pcap)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	codeParts := []string{fmt.Sprintf("%d", bpfProg.bf_len)}
	for _, v := range (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len] {
		codeParts = append(codeParts, fmt.Sprintf("%d %d %d %d", v.code, v.jt, v.jf, v.k))
	}
	return strings.Join(codeParts, ","), nil

}

func setupBpfObjects() (objs *bpfObjects, err error) {
	spec, err := loadBpf()
	if err != nil {
		return
	}

	ns, err := netns.Get()
	if err != nil {
		return
	}

	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
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

	objs = &bpfObjects{}
	if err = spec.LoadAndAssign(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			err = fmt.Errorf("%+v: %+v\n", err, ve)
		}
		return
	}

	return
}
