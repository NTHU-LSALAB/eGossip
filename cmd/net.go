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
	if nodeList.Protocol == "TCP" {
		tcpListen(nodeList, mq)
	} else if nodeList.Protocol == "UDP" {
		udpListen(nodeList, mq)
	} else {
		xdpListen(nodeList, mq)
	}
}
