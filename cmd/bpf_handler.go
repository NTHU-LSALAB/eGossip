package cmd

import (
	"log"

	"github.com/cilium/ebpf/link"
	bpf "github.com/kerwenwwer/xdp-gossip/bpf"
	"github.com/vishvananda/netlink"
)

func ProgramHandler(LinkName string, obj *bpf.BpfObjects) link.Link {
	// Get netlink by name
	link, err := netlink.LinkByName(LinkName)
	if err != nil {
		log.Fatalf("[Error]: Failed to get link by name %v", err)
	}

	// Attach Tc program
	if err := bpf.AttachTC(obj, link); err != nil {
		log.Fatalf("[Error]: Failed to attach TC: %v", err)
	}

	log.Printf("[Info]: TC attached")

	//Attach XDP program
	l := bpf.AttachXDP(obj, LinkName)
	if err := bpf.XdpPushToMap(obj, uint32(0), int64(0)); err != nil {
		log.Fatalf("[Error]: Failed to push metadata to map: %v", err)
	}

	log.Printf("[Info]: XDP attached")

	return l
}
