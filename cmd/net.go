package cmd

import "fmt"

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
		fmt.Println("Fastbroadcast not support TCP.")
	} else if nodeList.Protocol == "UDP" {
		udpListen(nodeList, mq)
	} else {
		fmt.Println("Protocol not supported")
	}
}
