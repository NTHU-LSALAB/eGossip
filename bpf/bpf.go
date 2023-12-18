package bpf

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/asavie/xdp"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"
	common "github.com/kerwenwwer/xdp-gossip/common"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	MAX_TARGETS = 64
)

type TargetInfoInterface interface {
	GetIp() uint32
	GetPort() uint16
	GetMac() [6]int8
}

type BpfObjects struct {
	objs *bpfObjects
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" bpf ./bpf.c

// Configuration of QdiscAttrs for clsact qdisc and replace default value (typically is noqueue)
func replaceQdisc(link netlink.Link) error {
	// - LinkIndex specifies the network interface where the qdisc is applied.
	// - Handle is set to a standard value for clsact, which doesn't require a unique identifier.
	// - Parent is set to HANDLE_CLSACT, positioning clsact at the ingress/egress, not in a qdisc hierarchy.
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	// Setting up clsact qdisc type for eBPF program attachment

	// Initializes a clsact qdisc, which is specialized for direct packet processing at
	// ingress and egress points without involving traffic scheduling. This is ideal for
	// eBPF programs due to clsact's immediate action capabilities on packets, enhancing
	// network control flexibility and performance.
	//
	// - clsact is chosen for its efficiency in executing actions (like eBPF programs) directly,
	//   bypassing traditional traffic management and scheduling.
	// - Essential for scenarios requiring dynamic, high-performance packet manipulation.
	//
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func LoadObjects() (*BpfObjects, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "Verifier errors:\n%s\n", ve.Error())
		}
		return nil, err
	}

	return &BpfObjects{&objs}, nil
}

func AttachTC(BpfObjs *BpfObjects, link netlink.Link) error {
	if err := replaceQdisc(link); err != nil {
		return err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           BpfObjs.objs.Fastbroadcast.FD(),
		Name:         fmt.Sprintf("%s-%s", "fastboradcast_prog", link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return err
	}

	return nil
}

func RemoveTC(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}

func AttachXDP(BpfObjs *BpfObjects, Ifindex int) (*xdp.Program, error) {
	// Create XDP program
	p := &xdp.Program{Program: BpfObjs.objs.bpfPrograms.XdpSockProg,
		Queues:  BpfObjs.objs.bpfMaps.QidconfMap,
		Sockets: BpfObjs.objs.bpfMaps.XsksMap}

	// Attach XDP program to interface
	if err := p.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return nil, err
	}

	//log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	return p, nil
}

func TcPushtoMap(BpfObjs *BpfObjects, key uint16, targets []common.Node) error {
	mapRef := BpfObjs.objs.TargetsMap
	var value bpfTargets

	var targetCount int
	for _, v := range targets {
		if v.Addr != "" {
			targetCount++
		}
	}
	//fmt.Println("targetCount", targetCount)

	if targetCount > MAX_TARGETS {
		return fmt.Errorf("too many targets: %d", targetCount)
	}

	value.MaxCount = uint16('0' + targetCount - 1)
	//fmt.Println("value.MaxCount", value.MaxCount)

	//fmt.Println("targets: ", targets)

	i := 0

	for _, v := range targets {
		if i >= MAX_TARGETS {
			log.Fatalf("too many targets: %d", i)
			break
		}

		//fmt.Println(v)

		value.TargetList[i].Ip = common.IpToUint32(v.Addr)
		value.TargetList[i].Port = uint16(v.Port)
		value.TargetList[i].Mac = common.MacStringToInt8Array(v.Mac)

		i++
	}

	//fmt.Println("count", i, targetCount)

	//fmt.Println("BC value", value)

	if err := mapRef.Put(key, value); err != nil {
		return err
	}
	return nil
}

// func XdpPushToMap(BpfObjs *BpfObjects, key uint32, value int64) error {
// 	mapRef := BpfObjs.objs.MetadataMap

// 	if err := mapRef.Put(key, value); err != nil {
// 		return err
// 	}
// 	return nil
// }
