package cmd

import (
	"encoding/json"
	"strconv"
	"time"

	bpf "github.com/kerwenwwer/xdp-gossip/bpf"
	common "github.com/kerwenwwer/xdp-gossip/common"
)

// Periodic heartbeat broadcast task
func task(nodeList *NodeList) {
	for {
		// Stop syncing
		if !nodeList.status.Load().(bool) {
			break
		}

		// Add the local node to the list of infected nodes
		var infected = make(map[string]bool)
		infected[nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port)] = true

		// Update local node information
		nodeList.Set(nodeList.localNode)

		// Set up the heartbeat data packet
		p := common.Packet{
			Node:      nodeList.localNode,
			Infected:  infected,
			SecretKey: nodeList.SecretKey,
		}

		// Broadcast the heartbeat data packet
		broadcast(nodeList, p)

		//nodeList.println("[Print local nodeList]: ", nodeList.nodes)
		// Initiate a data exchange request with a node in the cluster
		swapRequest(nodeList)

		// Interval time
		time.Sleep(time.Duration(nodeList.Cycle) * time.Second)
	}
}

// Listen to synchronization information from other nodes
func listener(nodeList *NodeList, mq chan []byte) {
	// Listen coroutine
	listen(nodeList, mq)
}

// Consume messages
func consume(nodeList *NodeList, mq chan []byte) {
	for {
		// Retrieve message from the listen queue
		bs := <-mq

		if nodeList.Protocol == "XDP" {
			//nodeList.println("SrcIP: ", net.IP(bs[26:30]).String(), ", SrcPort: ", int(bs[34])*256+int(bs[35]),
			//	", DstIP: ", net.IP(bs[30:34]).String(), ", DstPort: ", int(bs[36])*256+int(bs[37]), "payload:", string(bs[42:]))

			// if net.IP(bs[30:34]).String() != nodeList.localNode.Addr {
			// 	log.Fatalf("[ERROR] DstIP is not local IP")
			// }
			bs[60] = byte('0')
			//nodeList.println("Count: ", string(bs[42:65]))

			bs = bs[42:] // Only need payload
		}

		var p common.Packet
		err := json.Unmarshal(bs, &p)

		//nodeList.println(p.Count)
		// If data parsing error
		if err != nil {
			//nodeList.println("[Consumer Data Parsing Error]:", err)
			nodeList.println("[Consumer Data Parsing Error]:", err, string(bs))
			// Skip
			continue
		}

		// If the packet's secret key does not match the current node's secret key
		if p.SecretKey != nodeList.SecretKey {
			nodeList.println("[Error]:", "The secretKey do not match")
			// Skip, do not process this packet
			continue
		}

		// If the packet is for metadata exchange between two nodes
		if p.Type >= 2 {
			// If the version of the metadata in the packet is newer than the local metadata
			if p.Metadata.Update > nodeList.metadata.Load().(common.Metadata).Update {
				// Update local node's stored metadata
				nodeList.metadata.Store(p.Metadata)
				// Skip, do not broadcast, do not respond to initiator

				nodeList.println("[Metadata]: Recv new node metadata, node info:", nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port))

				continue
			}
			// If the packet's metadata version is older, this means the initiator's metadata version needs to be updated
			if p.Metadata.Update < nodeList.metadata.Load().(common.Metadata).Update {
				// If it is a swap request from the initiator
				if p.Type == 2 {
					// Respond to the initiator, send the latest metadata to the initiator, complete the swap process
					swapResponse(nodeList, p.Node)
				}
			}
			// Skip, do not broadcast
			if p.Metadata.Update == nodeList.metadata.Load().(common.Metadata).Update {
				nodeList.println("Metadat is same, skip")
			}
			continue
		}

		// Retrieve node information from the heartbeat packet
		node := p.Node

		// Update local list
		nodeList.Set(node)

		// If the packet is a metadata update and the metadata version in the packet is newer than the local metadata
		if p.IsUpdate && p.Metadata.Update > nodeList.metadata.Load().(common.Metadata).Update {
			// Update local node's stored metadata
			nodeList.metadata.Store(p.Metadata)
			nodeList.println("[Metadata]: Recv new node metadata, node info:", nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port))
		}

		// Broadcast this node's information
		broadcast(nodeList, p)

	}
}

// Broadcast information
func broadcast(nodeList *NodeList, p common.Packet) {

	if nodeList.Protocol == "XDP" {
		fastBroadcast(nodeList, p)
		return
	}

	p.Type = 1
	// Get all unexpired nodes
	nodes := nodeList.Get()

	var targetNodes []common.Node

	// Select some uninfected nodes
	i := 0
	for _, v := range nodes {

		// If the maximum number of pushes (Amount) has been reached
		if i >= nodeList.Amount {
			// Stop the broadcast
			break
		}

		// If the node has already been "infected"
		if p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] {
			// Skip this node
			continue
		}

		p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] = true // Mark the node as infected
		// Set the target node for sending
		targetNode := common.Node{
			Addr: v.Addr, // Set the target address
			Port: v.Port, // Set the target port
		}

		// Add the node to the broadcast list
		targetNodes = append(targetNodes, targetNode)
		i++
	}

	//nodeList.println("[Broadcast]:", len(targetNodes))

	// Broadcast the "infection" data to these uninfected nodes
	for _, v := range targetNodes {
		bs, err := json.Marshal(p)
		if err != nil {
			nodeList.println("[Infection Error]:", err)
		}

		// Send the packet
		write(nodeList, v.Addr, v.Port, bs)
	}
}

func fastBroadcast(nodeList *NodeList, p common.Packet) {
	nodes := nodeList.Get()
	var targetNodes []common.Node

	// Select some uninfected nodes
	i := 0

	for _, v := range nodes {

		// If the maximum number of pushes (Amount) has been reached
		if i >= nodeList.Amount {
			// Stop the broadcast
			break
		}

		if v.Addr == nodeList.localNode.Addr && v.Port == nodeList.localNode.Port {
			// Skip to broadcast to self
			continue
		}

		// If the node has already been "infected"
		if p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] {
			// Skip this node
			continue
		}

		p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] = true // Mark the node as infected
		// Set the target node for sending
		targetNode := common.Node{
			Addr: v.Addr, // Set the target address
			Port: v.Port, // Set the target port
			Mac:  v.Mac,  // Set the target mac
		}

		// Add the node to the broadcast list
		targetNodes = append(targetNodes, targetNode)
		i++
	}

	//nodeList.println("[Broadcast]:", len(targetNodes))

	if len(targetNodes) != 0 {
		/* Handle atomic counter operation for map_id*/
		map_id := nodeList.Counter.Next()
		if map_id == 0 {
			nodeList.println("[Map ID error]: map_id is 0")
		}
		p.Mapkey = map_id
		p.Type = 1

		if err := bpf.TcPushtoMap(nodeList.Program, map_id, targetNodes); err != nil {
			nodeList.println("[TC error]:", "Failed to push to map", err)
		}

		bs, err := json.Marshal(p)
		if err != nil {
			nodeList.println("[Infection Error]:", err)
		}

		addr := targetNodes[0].Addr
		port := targetNodes[0].Port

		write(nodeList, addr, int(port), bs) // Send the packet
	} else {
		//nodeList.println("[Not target]:", "No target nodes")
	}
}

// Initiate a data exchange request between two nodes
func swapRequest(nodeList *NodeList) {

	// Set up a swap packet
	p := common.Packet{
		// Include local node info in the packet, the receiver uses this to respond to the request
		Type:      2,
		Node:      nodeList.localNode,
		Infected:  make(map[string]bool),
		Metadata:  nodeList.metadata.Load().(common.Metadata),
		SecretKey: nodeList.SecretKey,
	}

	// Fetch all unexpired nodes
	nodes := nodeList.Get()

	// Convert the packet to JSON
	bs, err := json.Marshal(p)
	if err != nil {
		nodeList.println("[Swap Request Parsing Error]:", err)
	}

	// Randomly select a node from the node list and initiate a data exchange request
	for i := 0; i < len(nodes); i++ {
		// If the node is the local node, skip it
		if nodes[i].Addr == nodeList.localNode.Addr && nodes[i].Port == nodeList.localNode.Port {
			continue
		}
		// Send the request
		write(nodeList, nodes[i].Addr, nodes[i].Port, bs)

		if nodeList.IsPrint {
			nodeList.println("[Swap Request]:", nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port), "->", nodes[i].Addr+":"+strconv.Itoa(nodes[i].Port))
		}
		break
	}
}

// Receive a swap request and respond to the sender, completing the swap
func swapResponse(nodeList *NodeList, node common.Node) {
	// Set as a swap packet
	p := common.Packet{
		Type:      3,
		Node:      nodeList.localNode,
		Infected:  make(map[string]bool),
		Metadata:  nodeList.metadata.Load().(common.Metadata),
		SecretKey: nodeList.SecretKey,
	}

	bs, err := json.Marshal(p)
	if err != nil {
		nodeList.println("[Error]:", err)
	}

	// Respond to the initiating node
	write(nodeList, node.Addr, node.Port, bs)

	if nodeList.IsPrint {
		nodeList.println("[Swap Response]:", node.Addr+":"+strconv.Itoa(node.Port), "<-", nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port))
	}
}
