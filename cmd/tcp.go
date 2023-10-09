package cmd

import (
	"fmt"
	"net"
)

func tcpWrite(nodeList *NodeList, addr string, port int, data []byte) {

	tcpAddr := fmt.Sprintf("%s:%v", addr, port)
	server, err := net.ResolveTCPAddr("tcp4", tcpAddr)

	if err != nil {
		nodeList.println("[TCP Error]:", err)
		return
	}

	conn, err := net.DialTCP("tcp", nil, server)
	if err != nil {
		nodeList.println("[TCP Error]:", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		nodeList.println("[TCP Error]:", err)
	}

	defer func(conn *net.TCPConn) {
		err = conn.Close()
		if err != nil {
			nodeList.println("[TCP Error]:", err)
		}
	}(conn)
}

func tcpListen(nodeList *NodeList, mq chan []byte) {
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%v", nodeList.ListenAddr, nodeList.localNode.Port))
	if err != nil {
		nodeList.println("[TCP Error]:", err)
		return
	}
	defer func(server net.Listener) {
		err = server.Close()
		if err != nil {
			nodeList.println("[TCP Error]:", err)
		}
	}(server)

	for {
		conn, err := server.Accept()
		if err != nil {
			continue
		}
		go func() {

			bs := make([]byte, nodeList.Size)
			n, err := conn.Read(bs)
			if err != nil {
				nodeList.println("[TCP Error]:", err)
				return
			}

			if n >= nodeList.Size {
				nodeList.println("[TCP Error]:", fmt.Sprintf("received data size (%v) exceeds the limit (%v)", n, nodeList.Size))
				return
			}

			b := bs[:n]

			mq <- b
		}()
	}
}
