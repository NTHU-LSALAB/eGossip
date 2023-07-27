package cmd

import (
	"fmt"
	//"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	ebpf "github.com/kerwenwwer/xdp-gossip/bpf"
)

var limits = make(chan []byte)
var count int
var multipleReceiver int

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
		// recive data
		bs := make([]byte, nodeList.Size)

		// listen for UDP packets to the port
		start := time.Now()
		n, _, err := conn.ReadFromUDP(bs)
		if err != nil {
			nodeList.println("[Error]:", err)
			continue
		}

		if n >= nodeList.Size {
			nodeList.println("[Error]:", fmt.Sprintf("received data size (%v) exceeds the limit (%v)", n, nodeList.Size))
			continue
		}

		//get data
		b := bs[:n]

		// put data in to a message queue
		mq <- b

		elapsed := time.Since(start)
		nodeList.println("Latency for packet: ", elapsed)
	}
}

// func initXdp(nodeList *NodeList) {

// }

func udpprocess(mq chan []byte) {
	for pktData := range limits {
		// PAYLOAD
		_ = pktData
		count++
		//log.Println(count)
		mq <- pktData[42:]
		// log.Print(
		// 	"SrcIP: ", net.IP(pktData[26:30]).String(), ", SrcPort: ", int(pktData[34])*256+int(pktData[35]),
		// 	", DstIP: ", net.IP(pktData[30:34]).String(), ", DstPort: ", int(pktData[36])*256+int(pktData[37]),
		// 	", Data: ", string(pktData[42:]),
		// )
	}
}

func xdpListen(nodeList *NodeList, mq chan []byte) {
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

	if err := localNode.Program.Register(queueID, xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer localNode.Program.Unregister(queueID)

	// Set up a goroutine to read packets from the XDP socket and send them
	multipleReceiver = 1
	for i := 0; i < multipleReceiver; i++ {
		go udpprocess(mq)
	}

	// log.Println("Start UDP Server: linkname:", linkName, "Port:", port)

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		localNode.Program.Detach(Ifindex)
		os.Exit(1)
	}()

	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n))
		}
		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		// log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)
			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				receivedTime := time.Now() // Time of reception
				pktData := xsk.GetFrame(rxDescs[i])
				processedTime := time.Now() // Time of processing
				latency := processedTime.Sub(receivedTime)
				nodeList.println("Latency for packet: ", latency)
				limits <- pktData
			}
		}
	}
}
