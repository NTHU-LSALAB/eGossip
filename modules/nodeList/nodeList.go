package nodeList

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asavie/xdp"
	"github.com/kerwenwwer/eGossip/modules/encrypt"
	bpf "github.com/kerwenwwer/eGossip/pkg/bpf"
	common "github.com/kerwenwwer/eGossip/pkg/common"
	logger "github.com/kerwenwwer/eGossip/pkg/logger"
)

// NodeList is a list of nodes
type NodeList struct {
	nodes   sync.Map // Collection of nodes (key is Node structure, value is the most recent second-level timestamp of node update)
	Amount  int      // Number of nodes to send synchronization information to at one time
	Cycle   int64    // Synchronization cycle (how many seconds to send list synchronization information to other nodes)
	Buffer  int      // UDP/TCP receive buffer size (determines how many requests the UDP/TCP listening service can process asynchronously)
	Size    int      // Maximum capacity of a single UDP/TCP heartbeat packet (in bytes)
	Timeout int64    // Expiry deletion limit for a single node (delete after how many seconds)

	SecretKey string // Cluster key, the keys of all nodes in the same cluster should be consistent

	LocalNode common.Node // Local node information

	Protocol   string // Network protocol used by the cluster connection, UDP or TCP, XDP(UDP based with ebpf feature) default is UDP
	ListenAddr string // Local UDP/TCP listening address, use this address to receive heartbeat packets from other nodes (usually 0.0.0.0 is sufficient)

	status atomic.Value // Status of local node list update (true: running normally, false: stop publishing heartbeat)

	IsPrint bool // Whether to print list synchronization information to the console

	metadata atomic.Value // Metadata, the metadata content of each node in the cluster is consistent, equivalent to the public data of the cluster (can store some common configuration information), can update the metadata content of each node through broadcasting

	Program *bpf.BpfObjects       // bpf program
	Xsk     *xdp.Socket           // xdp socket
	Counter *common.AtomicCounter // bpf program key counter

	GatewayMAC string // gateway mac address
	Logger     *logger.Logger
}

const errMsgControlErrorPrefix = "[Control Error]:"

// New initializes the local node list
func (nodeList *NodeList) New(localNode common.Node) {

	// Addr default value: 0.0.0.0
	if localNode.Addr == "" {
		localNode.Addr = "0.0.0.0"
	}

	// ListenAddr default value: 0.0.0.0
	if nodeList.ListenAddr == "" {
		nodeList.ListenAddr = localNode.Addr
	}

	// Amount default value: 3
	if nodeList.Amount == 0 {
		nodeList.Amount = 30
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
		nodeList.Timeout = nodeList.Cycle*5 + 2
	}

	// If the key setting is not empty, then encrypt the key with md5
	if nodeList.SecretKey != "" {
		nodeList.SecretKey = encrypt.Md5Sign(nodeList.SecretKey)
	}

	// Initialize the basic data of the local node list
	nodeList.nodes.Store(localNode, time.Now().Unix()) // Add local node information into the node collection
	nodeList.LocalNode = localNode                     // Initialize local node information
	nodeList.status.Store(true)                        // Initialize node service status

	// Set metadata information
	md := common.Metadata{
		Data:   []byte(""), // Metadata content
		Update: 0,          // Metadata update timestamp
	}
	nodeList.metadata.Store(md) // Initialize metadata information

	// Store atomic counter for bpf map key
	nodeList.Counter = common.NewAtomicCounter()
}

// Join joins the cluster
func (nodeList *NodeList) Join() {

	// If the local node list of this node has not been initialized
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Join().")
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

	nodeList.Logger.Sugar().Infoln("[Control]: Join signal for ", nodeList.LocalNode)
}

// Stop stops the broadcasting of heartbeat
func (nodeList *NodeList) Stop() {

	// If the local node list of this node has not been initialized
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Stop().")
		// Return directly
		return
	}

	nodeList.Logger.Sugar().Infoln("[Control]: Stop signal for ", nodeList.LocalNode)
	nodeList.status.Store(false)
}

// Start restarts the broadcasting of heartbeat
func (nodeList *NodeList) Start() {

	// If the local node list of this node has not been initialized
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Start().")
		// Return directly
		return
	}

	// If the current heartbeat service is normal
	if nodeList.status.Load().(bool) {
		// Return directly
		return
	}
	nodeList.Logger.Sugar().Infoln("[Control]: Start signal for ", nodeList.LocalNode)
	nodeList.status.Store(true)
	// Periodically broadcast local node information
	go task(nodeList)
}

// Set adds other nodes to the local node list
func (nodeList *NodeList) Set(node common.Node) {

	// If the local node list of this node has not been initialized
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Set().")
		// Return directly
		return
	}

	// If new node has different subnet, set mac address to gateway mac
	samesub, _ := common.IsSameSubnet(node.Addr, nodeList.LocalNode.Addr, "255.255.255.0")
	if !samesub {
		node.Mac = nodeList.GatewayMAC
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
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Get().")
		// Return directly
		return nil
	}

	var nodes []common.Node
	// Traverse all key-value pairs in sync.Map
	nodeList.nodes.Range(func(k, v interface{}) bool {
		//If this node has not been updated for a while, delete it
		if v.(int64)+nodeList.Timeout < time.Now().Unix() {
			nodeList.nodes.Delete(k)
			nodeList.Logger.Sugar().Warnln("[[Timeout]:", k, "has been deleted]")
		} else {
			nodes = append(nodes, k.(common.Node))
		}
		return true
	})
	return nodes
}

// Publish publishes new metadata information in the cluster
func (nodeList *NodeList) Publish(newMetadata []byte) {

	//Return if the node's local node list has not been initialized
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Infoln(errMsgControlErrorPrefix, "New() a nodeList before Publish().")
		return
	}

	nodeList.Logger.Sugar().Infoln("[Control]: Metadata Publish in", nodeList.LocalNode, "/ [Metadata]:", newMetadata)

	// Add the local node to the infected node list
	var infected = make(map[string]bool)
	infected[nodeList.LocalNode.Addr+":"+strconv.Itoa(nodeList.LocalNode.Port)] = true

	// Update local node info
	nodeList.Set(nodeList.LocalNode)

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
		Node:     nodeList.LocalNode,
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
	if len(nodeList.LocalNode.Addr) == 0 {
		nodeList.Logger.Sugar().Panicln(errMsgControlErrorPrefix, "New() a nodeList before Read().")
		// Directly return
		return nil
	}

	return nodeList.metadata.Load().(common.Metadata).Data
}
