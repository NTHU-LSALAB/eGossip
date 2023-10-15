package bpf

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

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

func AttachXDP(BpfObjs *BpfObjects, linkname string) link.Link {
	iface, err := net.InterfaceByName(linkname)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", linkname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   BpfObjs.objs.bpfPrograms.Fastdrop,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	//log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	return l
}

func TcPushtoMap(BpfObjs *BpfObjects, key uint32, targets sync.Map) error {
	mapRef := BpfObjs.objs.TargetsMap
	var value bpfTargets

	var targetCount int
	targets.Range(func(_, _ interface{}) bool {
		targetCount++
		return true
	})
	//fmt.Println("targetCount", targetCount)

	if targetCount > MAX_TARGETS {
		return fmt.Errorf("too many targets: %d", targetCount)
	}

	value.MaxCount = uint16('0' + targetCount - 1)
	//fmt.Println("value.MaxCount", value.MaxCount)

	i := 0
	targets.Range(func(key, val interface{}) bool {
		if i >= MAX_TARGETS {
			return false
		}

		target, ok := key.(TargetInfoInterface)
		if !ok {
			// handle the error, maybe return
			return false
		}
		value.TargetList[i].Ip = target.GetIp()
		value.TargetList[i].Port = target.GetPort()
		value.TargetList[i].Mac = target.GetMac()

		i++
		return true
	})

	fmt.Println("BC value", value)

	if err := mapRef.Put(key, value); err != nil {
		return err
	}
	return nil
}

func XdpPushToMap(BpfObjs *BpfObjects, key uint32, value int64) error {
	mapRef := BpfObjs.objs.MetadataMap

	if err := mapRef.Put(key, value); err != nil {
		return err
	}
	return nil
}
