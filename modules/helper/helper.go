package helper

import (
	"log"

	"github.com/asavie/xdp"
	bpf "github.com/kerwenwwer/eGossip/pkg/bpf"
	common "github.com/kerwenwwer/eGossip/pkg/common"
	"github.com/vishvananda/netlink"
)

// New initializes the local node list
func ProgramHandler(LinkName string, obj *bpf.BpfObjects, debug bool, mode int) (*xdp.Program, *xdp.Socket) {
	// Get netlink by name
	link, err := netlink.LinkByName(LinkName)
	if err != nil {
		log.Fatalf("[BPF Handler]: Failed to get link by name %v", err)
	}

	// Attach Tc program
	if err := bpf.AttachTC(obj, link); err != nil {
		log.Fatalf("[BPF Handler]: Failed to attach TC: %v", err)
	}

	if debug {
		log.Printf("[BPF Handler]: TC program attached. ")
	}

	// If mode is 0, return program only (no need to create AF_XDP socket)
	if mode == 0 {
		return nil, nil
	}

	//Attach XDP program
	program, err := bpf.AttachXDP(obj, link.Attrs().Index)
	if err != nil {
		log.Fatalf("[BPF Handler]: Failed to attach XDP: %v", err)
	}

	// Create AF_XDP socket
	xsk, err := xdp.NewSocket(link.Attrs().Index, 0, &xdp.SocketOptions{
		NumFrames:              256,
		FrameSize:              4096,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	})
	if err != nil {
		log.Fatal("[BPF Handler]: error: failed to create an XDP socket: ", err)
	}

	if err := program.Register(0, xsk.FD()); err != nil {
		log.Fatal("[BPF Handler]: error: failed to register socket in BPF map: ", err)
	}
	defer program.Unregister(0)

	if debug {
		log.Printf("[BPF Handler]: AF_XDP program registered.")
	}

	return program, xsk
}

type MyPacket common.Packet
