package cmd

import (
	"sync"
	"sync/atomic"

	bpf "github.com/kerwenwwer/xdp-gossip/bpf"
)

// NodeList is a list of nodes
type NodeList struct {
	nodes           sync.Map // Collection of nodes (key is Node structure, value is the most recent second-level timestamp of node update)
	broadcastTarget sync.Map // Broadcast target

	Amount  int   // Number of nodes to send synchronization information to at one time
	Cycle   int64 // Synchronization cycle (how many seconds to send list synchronization information to other nodes)
	Buffer  int   // UDP/TCP receive buffer size (determines how many requests the UDP/TCP listening service can process asynchronously)
	Size    int   // Maximum capacity of a single UDP/TCP heartbeat packet (in bytes)
	Timeout int64 // Expiry deletion limit for a single node (delete after how many seconds)

	SecretKey string // Cluster key, the keys of all nodes in the same cluster should be consistent

	localNode Node // Local node information

	Protocol   string // Network protocol used by the cluster connection, UDP or TCP, XDP(UDP based with ebpf feature) default is UDP
	ListenAddr string // Local UDP/TCP listening address, use this address to receive heartbeat packets from other nodes (usually 0.0.0.0 is sufficient)

	status atomic.Value // Status of local node list update (true: running normally, false: stop publishing heartbeat)

	IsPrint bool // Whether to print list synchronization information to the console

	metadata atomic.Value // Metadata, the metadata content of each node in the cluster is consistent, equivalent to the public data of the cluster (can store some common configuration information), can update the metadata content of each node through broadcasting

	Program *bpf.BpfObjects // bpf program
}

// Node represents a node
type Node struct {
	Addr        string `json:"Addr"`        // Node IP address (fill in public IP in public network environment)
	Port        int    `json:"Port"`        // Port number
	Name        string `json:"Name"`        // Node name (customizable)
	PrivateData string `json:"PrivateData"` // Node private data (customizable)
	LinkName    string // bind xdp to this interface
}

type BroadcastTargets struct {
	Ip   uint32
	Port uint16
	Mac  [6]int8
}

func (t BroadcastTargets) GetIp() uint32 {
	return t.Ip
}

func (t BroadcastTargets) GetPort() uint16 {
	return t.Port
}

func (t BroadcastTargets) GetMac() [6]int8 {
	return t.Mac
}

// Packet data
type packet struct {
	Type  uint8  // 0: heartbeat packet, 1: metadata update packet , 2: initiator sends an exchange request to the recipient, 3: recipient responds to the initiator, data exchange completed
	Count uint16 // Broadcast packet count (0-64)
	// Metadata information
	Metadata metadata // New metadata information, if the packet is a metadata update packet (isUpdate=true), then replace the original cluster metadata with newData

	// Node information
	Node     Node            // Node information in the heartbeat packet
	Infected map[string]bool // List of nodes already infected by this packet, the key is a string concatenated by Addr:Port, and the value determines whether the node has been infected (true: yes, false: no)

	SecretKey string // Cluster key, if it doesn't match, reject processing this packet
	CountStr  string
}

// Metadata information
type metadata struct {
	Update int64  // Metadata version (update timestamp)
	Data   []byte // Metadata content
}
