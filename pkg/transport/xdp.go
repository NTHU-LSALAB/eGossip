package transport

import (

	//"log"

	"github.com/asavie/xdp"
	"github.com/kerwenwwer/eGossip/pkg/logger"
)

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
			logger.NewNopLogger().Sugar().Panicln("error: %v\n", err)
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
