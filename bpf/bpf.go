package xdp_sock

import (
	"fmt"
	"log"
	"net"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// // See accompanying Makefile + Dockerfile to make updates.

//go:generate $HOME/go/bin/bpf2go bpf bpf.c -- -I/usr/include/ -nostdinc -O3 -g -Wall -Werror -Wno-unused-value -Wno-pointer-sign -Wcompare-distinct-pointer-types

type Program uint8

const (
	ProgramNone Program = iota
	XdpSockProg
	FastboradcastProg
)

// Load BPF object
func LoadBpfOBj() (*bpfObjects, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	return &objs, nil
}

// // Attach BPF object
func Attach(obj *bpfObjects, prog Program, linkName string) (func(), xdp.Program, error) {

	switch prog {
	case XdpSockProg:
		return attachXdpSockPrgo(obj.XdpSockProg, Ifindex)
	case FastboradcastProg:
		return attachFastboradcastProg(obj.FastboradcastProg, Ifindex)
	}

	return nil, nil, fmt.Errorf("unknow program %d\n", prog)
}

func attachXdpSockPrgo(p *ebpf.Program, Ifindex int) (func(), xdp.Program, error) {
	xdp_prog := &xdp.Program{Program: p., Queues: p.QidconfMap, Sockets: p.XsksMap}

	return func() {
		if err != l.Close(); err != nil {
			log.Printf("error: failed to close xdp socket: %v\n", err)
		}
	}, xdp_prog, nil
}

func attachFastboradcastProg(p *ebpf.Program, Ifindex int) (func(), xdp.Program, error) {
	return func() {
		if err != l.Close(); err != nil {
			log.Printf("error: failed to close fastboradcast socket: %v\n", err)
		}
	}, nil, nil
}

func FindIfindex(linkname string) (int, error) {
	var Ifindex int
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return -1, err
	}
	for _, iface := range interfaces {
		if iface.Name == linkname {
			Ifindex = iface.Index
			break
		}
	}
	return Ifindex, nil
}

func NewUDPPortProgram(dest uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}

	if dest > 0 && dest <= 65535 {
		if err := spec.RewriteConstants(map[string]interface{}{"PORT": uint16(dest)}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}

	var program bpfObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &xdp.Program{Program: program.XdpSockProg, Queues: program.QidconfMap, Sockets: program.XsksMap}
	return p, nil
}
