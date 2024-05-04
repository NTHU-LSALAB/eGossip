package transport

import (
	"fmt"

	//"log"
	"net"

	"github.com/asavie/xdp"
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

func XdpListen(xsk *xdp.Socket, mq chan []byte) {
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
				mq <- pktData
			}
		}
	}
}
