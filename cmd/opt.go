package cmd

import (
	"strconv"
	"time"

	common "github.com/kerwenwwer/xdp-gossip/common"
)

// New initializes the local node list
func (nodeList *NodeList) New(localNode common.Node) {

	// Addr default value: 0.0.0.0
	if localNode.Addr == "" {
		localNode.Addr = "0.0.0.0"
	}

	// Protocol default value: UDP
	// if nodeList.Protocol != "TCP" || nodeList.Protocol != "XDP" {
	// 	nodeList.Protocol = "UDP"
	// }

	// ListenAddr default value: 0.0.0.0
	if nodeList.ListenAddr == "" {
		nodeList.ListenAddr = localNode.Addr
	}

	// Amount default value: 3
	if nodeList.Amount == 0 {
		nodeList.Amount = 64
	}

	// Cycle default value: 6
	if nodeList.Cycle == 0 {
		nodeList.Cycle = 6
	}

	// Buffer default value: if not filled, the default is equal to Amount multiplied by 3
	if nodeList.Buffer == 0 {
		nodeList.Buffer = nodeList.Amount * 3
	}

	// Size default value: 16384
	if nodeList.Size == 0 {
		nodeList.Size = 16384
	}

	// Timeout default value: if the current Timeout is less than or equal to Cycle, then automatically enlarge the value of Timeout
	if nodeList.Timeout <= nodeList.Cycle {
		nodeList.Timeout = nodeList.Cycle*3 + 2
	}

	// If the key setting is not empty, then encrypt the key with md5
	if nodeList.SecretKey != "" {
		nodeList.SecretKey = md5Sign(nodeList.SecretKey)
	}

	// Initialize the basic data of the local node list
	nodeList.nodes.Store(localNode, time.Now().Unix()) // Add local node information into the node collection
	nodeList.localNode = localNode                     // Initialize local node information
	nodeList.status.Store(true)                        // Initialize node service status

	// Set metadata information
	md := common.Metadata{
		Data:   []byte(""), // Metadata content
		Update: 0,          // Metadata update timestamp
	}
	nodeList.metadata.Store(md) // Initialize metadata information

	// Store atomic counter for bpf map key
	nodeList.Counter = common.NewAtomicCounter()

	// Load bpf objects
}

// Join joins the cluster
func (nodeList *NodeList) Join() {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Directly return
		return
	}

	// Periodically broadcast local node information
	go task(nodeList)

	// Listen queue (UDP listen buffer)
	var mq = make(chan []byte, nodeList.Buffer)

	// Listen for information from other nodes and put it into the mq queue
	go listener(nodeList, mq)

	// Consume the information in the mq queue
	go consume(nodeList, mq)

	nodeList.println("[Join]:", nodeList.localNode)
}

// Stop stops the broadcasting of heartbeat
func (nodeList *NodeList) Stop() {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Return directly
		return
	}

	nodeList.println("[Stop]:", nodeList.localNode)
	nodeList.status.Store(false)
}

// Start restarts the broadcasting of heartbeat
func (nodeList *NodeList) Start() {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Return directly
		return
	}

	// If the current heartbeat service is normal
	if nodeList.status.Load().(bool) {
		// Return directly
		return
	}
	nodeList.println("[Start]:", nodeList.localNode)
	nodeList.status.Store(true)
	// Periodically broadcast local node information
	go task(nodeList)
}

// Set adds other nodes to the local node list
func (nodeList *NodeList) Set(node common.Node) {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Return directly
		return
	}

	if node.Addr == "" {
		node.Addr = "0.0.0.0"
	}

	// Store node information
	nodeList.nodes.Store(node, time.Now().Unix())
}

// Get retrieves the local node list
func (nodeList *NodeList) Get() []common.Node {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Return directly
		return nil
	}

	var nodes []common.Node
	// Traverse all key-value pairs in sync.Map
	nodeList.nodes.Range(func(k, v interface{}) bool {
		//If this node has not been updated for a while
		// if v.(int64)+nodeList.Timeout < time.Now().Unix() {
		// 	nodeList.nodes.Delete(k)
		// 	nodeList.println("[[Timeout]:", k, "has been deleted]")
		// } else {
		nodes = append(nodes, k.(common.Node))
		// }
		return true
	})
	return nodes
}

// Publish publishes new metadata information in the cluster
func (nodeList *NodeList) Publish(newMetadata []byte) {

	//Return if the node's local node list has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		return
	}

	nodeList.println("[Publish]:", nodeList.localNode, "/ [Metadata]:", newMetadata)

	// Add the local node to the infected node list
	var infected = make(map[string]bool)
	infected[nodeList.localNode.Addr+":"+strconv.Itoa(nodeList.localNode.Port)] = true

	// Update local node info
	nodeList.Set(nodeList.localNode)

	// Set new metadata
	md := common.Metadata{
		Data:   newMetadata,
		Update: time.Now().UnixNano(), // Metadata update timestamps
		Size:   len(newMetadata),      // Metadata size
	}

	// // Update local node metadata info
	nodeList.metadata.Store(md)

	// // Set packet
	p := common.Packet{
		Node:     nodeList.localNode,
		Infected: infected,

		// Set the packet as metadata update packet
		Metadata: md,
		IsUpdate: true,

		SecretKey: nodeList.SecretKey,
	}

	// Broadcast packet in the cluster
	broadcast(nodeList, p)

}

// Read retrieves the metadata information from the local node list
func (nodeList *NodeList) Read() []byte {

	// If the local node list of this node has not been initialized
	if len(nodeList.localNode.Addr) == 0 {
		nodeList.println("[Error]:", "Please use the New() function first")
		// Directly return
		return nil
	}

	return nodeList.metadata.Load().(common.Metadata).Data
}
