package cmd

import (
	bpf "github.com/kerwenwwer/xdp-gossip/bpf"
	"github.com/vishvananda/netlink"
)

func TcHandler(nodeList *NodeList) {
	// Load bpf objects
	obj, err := bpf.LoadObjects()
	if err != nil {
		nodeList.println("[Error]:", "Failed to load objects: %v", err)
	}

	link, err := netlink.LinkByName(nodeList.localNode.LinkName)
	if err != nil {
		nodeList.println("[Error]:", "Failed to get link by name %v", err)
	}

	if err := bpf.AttachTC(obj, link); err != nil {
		nodeList.println("[Error]:", "Failed to attach TC: %v", err)
	}

	nodeList.println("[Info]:", "TC attached")
}
