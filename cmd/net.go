package cmd

// write
func write(nodeList *NodeList, addr string, port int, data []byte) {
	if nodeList.Protocol != "TCP" {
		udpWrite(nodeList, addr, port, data)
	} else {
		tcpWrite(nodeList, addr, port, data)
	}
}

// listen
func listen(nodeList *NodeList, mq chan []byte) {
	if nodeList.Protocol != "TCP" {
		//udpListen(nodeList, mq)
		xdpListen(nodeList, mq)
	} else {
		tcpListen(nodeList, mq)
	}
}
