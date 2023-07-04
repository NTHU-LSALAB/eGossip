package cmd

import (
	"fmt"
	"github.com/asavie/xdp"
	ebpf "github.com/kerwenwwer/xdp-gossip/bpf"
	"net"
)

// udpWrite send udp data
func udpWrite(nodeList *NodeList, addr string, port int, data []byte) {
	socket, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	})
	if err != nil {
		nodeList.println("[Error]:", err)
		return
	}

	_, err = socket.Write(data) // socket write syscall
	if err != nil {
		nodeList.println("[Error]:", err)
		return
	}

	defer func(socket *net.UDPConn) {
		err = socket.Close()
		if err != nil {
			nodeList.println("[Error]:", err)
		}
	}(socket)
}

// udpListen
func udpListen(nodeList *NodeList, mq chan []byte) {

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", nodeList.ListenAddr, nodeList.localNode.Port))
	if err != nil {
		nodeList.println("[Error]:", err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		nodeList.println("[Error]:", err)
		return
	}
	defer func(conn *net.UDPConn) {
		err = conn.Close()
		if err != nil {
			nodeList.println("[Error]:", err)
		}
	}(conn)

	for {
		//接收数组
		bs := make([]byte, nodeList.Size)

		//从UDP监听中接收数据
		n, _, err := conn.ReadFromUDP(bs)
		if err != nil {
			nodeList.println("[Error]:", err)
			continue
		}

		if n >= nodeList.Size {
			nodeList.println("[Error]:", fmt.Sprintf("received data size (%v) exceeds the limit (%v)", n, nodeList.Size))
			continue
		}

		//获取有效数据
		b := bs[:n]

		//将数据放入缓冲队列，异步处理数据
		mq <- b
	}
}

// func initXdp(nodeList *NodeList) {

// }

func xdpListen(nodeList *NodeList, mq chan []byte) {
	localNode := nodeList.localNode
	queueID := nodeList.localNode.queueID

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == localNode.linkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	localNode.program, err = ebpf.NewUDPPortProgram(uint32(nodeList.localNode.Port), nil)
	if err != nil {
		fmt.Printf("error: failed to create xdp program: %v\n", err)
		return
	}

	defer localNode.program.Close()
	if err := localNode.program.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer localNode.program.Detach(Ifindex)

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

	if err := localNode.program.Register(queueID, xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer localNode.program.Unregister(queueID)

}
