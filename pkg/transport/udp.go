package transport

import (
	"fmt"

	//"log"
	"net"

	logger "github.com/kerwenwwer/eGossip/pkg/logger"
)

const errMsgUDPErrorPrefix = "[UDP Error]:"

// udpWrite send udp data
func UdpWrite(logger *logger.Logger, addr string, port int, data []byte) {
	socket, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	})
	if err != nil {
		logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		return
	}

	_, err = socket.Write(data) // socket write syscall
	if err != nil {
		logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		return
	}

	defer func(socket *net.UDPConn) {
		err = socket.Close()
		if err != nil {
			logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		}
	}(socket)
}

// udpListen
func UdpListen(logger *logger.Logger, addr string, port int, size int, mq chan []byte) {

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		return
	}
	defer func(conn *net.UDPConn) {
		err = conn.Close()
		if err != nil {
			logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
		}
	}(conn)

	for {
		// recive data
		bs := make([]byte, size)

		// listen for UDP packets to the port
		n, _, err := conn.ReadFromUDP(bs)
		if err != nil {
			logger.Sugar().Panicln(errMsgUDPErrorPrefix, err)
			continue
		}

		if n >= size {
			logger.Sugar().Panicln(errMsgUDPErrorPrefix, fmt.Sprintf("received data size (%v) exceeds the limit (%v)", n, size))
			continue
		}

		//get data
		b := bs[:n]

		// put data in to a message queue
		mq <- b
	}
}
