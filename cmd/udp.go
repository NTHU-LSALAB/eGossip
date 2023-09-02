package cmd

import (
	"fmt"
	//"log"
	"net"
	"time"
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
