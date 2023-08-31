package cmd

import (
	"fmt"
	"github.com/asavie/xdp"
	ebpf "github.com/kerwenwwer/xdp-gossip/bpf"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func xdpInit(nodeList *NodeList) {
	localNode := nodeList.localNode
	queueID := nodeList.localNode.QueueID

	fmt.Printf("found interface %s\n", &localNode.LinkName)

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == localNode.LinkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	localNode.Program, err = ebpf.NewUDPPortProgram(uint32(nodeList.localNode.Port), nil)
	if err != nil {
		fmt.Printf("error: failed to create xdp program: %v\n", err)
		return
	}

	defer localNode.Program.Close()
	if err := localNode.Program.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer localNode.Program.Detach(Ifindex)

	// Create and initialize an XDP socket attached to our chosen network
	// link.
	xsk, err := xdp.NewSocket(Ifindex, queueID, &xdp.SocketOptions{
		NumFrames:              204800,
		FrameSize:              4096,
		FillRingNumDescs:       8192,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         8192,
		TxRingNumDescs:         64,
	})
	if err != nil {
		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
		return
	}

	localNode.Xsk = xsk

	if err := localNode.Program.Register(queueID, localNode.Xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer localNode.Program.Unregister(queueID)

	// log.Println("Start UDP Server: linkname:", linkName, "Port:", port)

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		localNode.Program.Detach(Ifindex)
		os.Exit(1)
	}()
}
