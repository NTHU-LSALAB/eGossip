package nodeList

import (
	"encoding/json"
	"strconv"
	"time"

	bpf "github.com/kerwenwwer/eGossip/pkg/bpf"
	common "github.com/kerwenwwer/eGossip/pkg/common"
	transport "github.com/kerwenwwer/eGossip/pkg/transport"
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
		infected[nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port)] = true

		// Update local node information
		nodeList.Set(nodeList.LocalNode)

		// Set up the heartbeat data packet
		p := common.Packet{
			Node:      nodeList.LocalNode,
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

		// Process XDP message (if applicable)
		if nodeList.Protocol == "XDP" {
			bs[60] = byte('0')
			bs = bs[42:] // Only need payload
		}

		// Unmarshal message and handle errors
		var p common.Packet
		if err := unmarshalPacket(bs, &p); err != nil {
			handleError(nodeList, err, bs)
			continue
		}

		// Validate packet and handle mismatches
		if !validatePacket(nodeList, p) {
			continue
		}

		// Process metadata update packets
		if processMetadataPacket(nodeList, p) {
			continue
		}

		// Process regular packets (update local list and broadcast)
		processRegularPacket(nodeList, p)
	}
}

func unmarshalPacket(bs []byte, p *common.Packet) error {
	return json.Unmarshal(bs, p)
}

func handleError(nodeList *NodeList, err error, bs []byte) {
	// Combine error logging (logic moved here)
	nodeList.Logger.Sugar().Panicln("[Consumer Data Parsing Error]:", err, string(bs))
}

func validatePacket(nodeList *NodeList, p common.Packet) bool {
	// Combine secret key and type checks (logic moved here)
	return p.SecretKey == nodeList.SecretKey && p.Type >= 0
}

func processMetadataPacket(nodeList *NodeList, p common.Packet) bool {
	if p.Type >= 2 {
		// If the version of the metadata in the packet is newer than the local metadata
		if p.Metadata.Update > nodeList.metadata.Load().(common.Metadata).Update {
			// Update local node's stored metadata
			nodeList.metadata.Store(p.Metadata)
			// Skip, do not broadcast, do not respond to initiator

			nodeList.Logger.Sugar().Infoln("[Metadata]: Recv new node metadata, node info:", nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port))
			return true
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
		return true
	}
	return false
}

func processRegularPacket(nodeList *NodeList, p common.Packet) {
	// Update local list and broadcast (logic moved here)
	node := p.Node
	//nodeList.println("[Recv]:", node.Addr+":"+strconv.Itoa(node.Port))
	nodeList.Set(node)
	if p.IsUpdate {
		nodeList.metadata.Store(p.Metadata)
		nodeList.Logger.Sugar().Infoln("[Metadata]: Recv new node metadata, node info:", nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port))
	}
	broadcast(nodeList, p)
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
			nodeList.Logger.Sugar().Panicln("[Infection Error]:", err)
		}

		// Send the packet
		write(nodeList, v.Addr, v.Port, bs)
	}
}

func fastBroadcast(nodeList *NodeList, p common.Packet) {
	nodes := nodeList.Get()
	var targetNodes []common.Node

	i := 0
	for _, v := range nodes {
		if i >= nodeList.Amount {
			break
		}

		if v.Addr == nodeList.LocalNode.Addr && v.Port == nodeList.LocalNode.Port {
			continue
		}

		if p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] {
			continue
		}

		p.Infected[v.Addr+":"+strconv.Itoa(v.Port)] = true
		targetNode := common.Node{Addr: v.Addr, Port: v.Port, Mac: v.Mac}
		targetNodes = append(targetNodes, targetNode)
		i++
	}

	// Function to split targetNodes into smaller slices if more than 25 nodes
	splitNodes := func(nodes []common.Node, size int) [][]common.Node {
		var chunks [][]common.Node
		for size < len(nodes) {
			nodes, chunks = nodes[size:], append(chunks, nodes[0:size:size])
		}
		chunks = append(chunks, nodes)
		return chunks
	}

	// Handling targetNodes exceeding 25 nodes
	if len(targetNodes) > 25 {
		nodeGroups := splitNodes(targetNodes, 25)

		for _, group := range nodeGroups {
			sendGroup(nodeList, group, p)
		}
	} else if len(targetNodes) != 0 {
		sendGroup(nodeList, targetNodes, p)
	}
}

// sendGroup handles sending a packet to a group of nodes
func sendGroup(nodeList *NodeList, nodes []common.Node, p common.Packet) {
	mapId := nodeList.Counter.Next()
	if mapId == 0 {
		nodeList.Logger.Sugar().Panicln("[Map ID error]: mapId is 0")
	}
	p.Mapkey = mapId
	p.Type = 1

	if err := bpf.TcPushtoMap(nodeList.Program, mapId, nodes); err != nil {
		nodeList.Logger.Sugar().Panicln("[TC error]:", "Failed to push to map", err)
	}

	bs, err := json.Marshal(p)
	if err != nil {
		nodeList.Logger.Sugar().Panicln("[Infection Error]:", err)
	}

	addr := nodes[0].Addr
	port := nodes[0].Port
	write(nodeList, addr, int(port), bs) // Send the packet to each node in the group
}

// Initiate a data exchange request between two nodes
func swapRequest(nodeList *NodeList) {

	// Set up a swap packet
	p := common.Packet{
		// Include local node info in the packet, the receiver uses this to respond to the request
		Type:      2,
		Node:      nodeList.LocalNode,
		Infected:  make(map[string]bool),
		Metadata:  nodeList.metadata.Load().(common.Metadata),
		SecretKey: nodeList.SecretKey,
	}

	// Fetch all unexpired nodes
	nodes := nodeList.Get()

	// Convert the packet to JSON
	bs, err := json.Marshal(p)
	if err != nil {
		nodeList.Logger.Sugar().Panicln("[Swap Request Parsing Error]:", err)
	}

	// Randomly select a node from the node list and initiate a data exchange request
	for i := 0; i < len(nodes); i++ {
		// If the node is the local node, skip it
		if nodes[i].Addr == nodeList.LocalNode.Addr && nodes[i].Port == nodeList.LocalNode.Port {
			continue
		}
		// Send the request
		write(nodeList, nodes[i].Addr, nodes[i].Port, bs)

		if nodeList.IsPrint {
			nodeList.Logger.Sugar().Infoln("[Swap Request]:", nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port), "->", nodes[i].Addr+":"+strconv.Itoa(nodes[i].Port))
		}
		break
	}
}

// Receive a swap request and respond to the sender, completing the swap
func swapResponse(nodeList *NodeList, node common.Node) {
	// Set as a swap packet
	p := common.Packet{
		Type:      3,
		Node:      nodeList.LocalNode,
		Infected:  make(map[string]bool),
		Metadata:  nodeList.metadata.Load().(common.Metadata),
		SecretKey: nodeList.SecretKey,
	}

	bs, err := json.Marshal(p)
	if err != nil {
		nodeList.Logger.Sugar().Panicln("[Error]:", err)
	}

	// Respond to the initiating node
	write(nodeList, node.Addr, node.Port, bs)

	if nodeList.IsPrint {
		nodeList.Logger.Sugar().Infoln("[Swap Response]:", node.Addr+":"+strconv.Itoa(node.Port), "<-", nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port))
	}
}

// write
func write(nodeList *NodeList, addr string, port int, data []byte) {
	transport.UdpWrite(nodeList.Logger, addr, port, data)
}

// listen
func listen(nodeList *NodeList, mq chan []byte) {
	if nodeList.Protocol == "UDP" || nodeList.Protocol == "TC" {
		transport.UdpListen(nodeList.Logger, nodeList.ListenAddr, nodeList.LocalNode.Port, nodeList.Size, mq)
	} else if nodeList.Protocol == "XDP" {
		transport.XdpListen(nodeList.Xsk, mq)
	} else {
		nodeList.Logger.Sugar().Panicln("Protocol not supported, only UDP, TC and XDP.")
	}
}
