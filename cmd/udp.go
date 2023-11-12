package cmd

import (
	"fmt"

	//"log"
	"net"
)

// udpWrite send udp data
func udpWrite(nodeList *NodeList, addr string, port int, data []byte) {
	socket, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	})
	if err != nil {
		nodeList.println("[UDP Error]:", err)
		return
	}

	_, err = socket.Write(data) // socket write syscall
	if err != nil {
		nodeList.println("[UDP Error]:", err)
		return
	}

	defer func(socket *net.UDPConn) {
		err = socket.Close()
		if err != nil {
			nodeList.println("[UDP Error]:", err)
		}
	}(socket)
}

// udpListen
func udpListen(nodeList *NodeList, mq chan []byte) {

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", nodeList.ListenAddr, nodeList.localNode.Port))
	if err != nil {
		nodeList.println("[UDP Error]:", err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		nodeList.println("[UDP Error]:", err)
		return
	}
	defer func(conn *net.UDPConn) {
		err = conn.Close()
		if err != nil {
			nodeList.println("[UDP Error]:", err)
		}
	}(conn)

	for {
		// recive data
		bs := make([]byte, nodeList.Size)

		// listen for UDP packets to the port
		//start := time.Now()
		n, _, err := conn.ReadFromUDP(bs)
		if err != nil {
			nodeList.println("[UDP Error]:", err)
			continue
		}

		if n >= nodeList.Size {
			nodeList.println("[UDP Error]:", fmt.Sprintf("received data size (%v) exceeds the limit (%v)", n, nodeList.Size))
			continue
		}

		//get data
		b := bs[:n]

		// put data in to a message queue
		mq <- b

		//elapsed := time.Since(start)
		//nodeList.println("Latency for packet: ", elapsed)
	}
}

func xdpListen(nodeList *NodeList, mq chan []byte) {

	// for i := 0; i < multipleReceiver; i++ {
	// 	go udpprocess(mq)
	// }

	xsk := nodeList.Xsk

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
				pktData := xsk.GetFrame(rxDescs[i])
				//log.Println(string(pktData))
				mq <- pktData
			}
		}
	}
}
