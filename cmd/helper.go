package cmd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

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

// IpToUint32 converts IP to uint32
func IpToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Failed to parse IP: %s", ipStr)
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip)
}

func (nl *NodeList) storeWithCheck(node Node) {
	nl.nodes.Range(func(k, v interface{}) bool {
		existingNode, ok := k.(Node)
		if ok && existingNode.Addr == node.Addr {
			fmt.Printf("Node with Addr %s already exists!\n", node.Addr)
			return false
		}
		return true
	})

	nl.nodes.Store(node, time.Now().Unix())
}

func (p *packet) MarshalJSON() ([]byte, error) {
	p.CountStr = string(p.Count)
	fmt.Printf("CountStr: %s\n", p.CountStr)
	type Alias packet
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(p),
	})
}
