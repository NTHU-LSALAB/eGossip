package cmd

import (
	"sync"
	"sync/atomic"

	"github.com/asavie/xdp"
)

// NodeList is a list of nodes
type NodeList struct {
	nodes sync.Map // Collection of nodes (key is Node structure, value is the most recent second-level timestamp of node update)

	Amount  int   // Number of nodes to send synchronization information to at one time
	Cycle   int64 // Synchronization cycle (how many seconds to send list synchronization information to other nodes)
	Buffer  int   // UDP/TCP receive buffer size (determines how many requests the UDP/TCP listening service can process asynchronously)
	Size    int   // Maximum capacity of a single UDP/TCP heartbeat packet (in bytes)
	Timeout int64 // Expiry deletion limit for a single node (delete after how many seconds)

	SecretKey string // Cluster key, the keys of all nodes in the same cluster should be consistent

	localNode Node // Local node information

	Protocol   string // Network protocol used by the cluster connection, UDP or TCP, default is UDP
	ListenAddr string // Local UDP/TCP listening address, use this address to receive heartbeat packets from other nodes (usually 0.0.0.0 is sufficient)

	status atomic.Value // Status of local node list update (true: running normally, false: stop publishing heartbeat)

	IsPrint bool // Whether to print list synchronization information to the console

	metadata atomic.Value // Metadata, the metadata content of each node in the cluster is consistent, equivalent to the public data of the cluster (can store some common configuration information), can update the metadata content of each node through broadcasting
}

// Node represents a node
type Node struct {
	Addr        string       `json:"Addr"`        // Node IP address (fill in public IP in public network environment)
	Port        int          `json:"Port"`        // Port number
	Name        string       `json:"Name"`        // Node name (customizable)
	PrivateData string       `json:"PrivateData"` // Node private data (customizable)
	LinkName    string       // bind xdp to this interface
	Program     *xdp.Program // XDP program
	Xsk         *xdp.Socket  // XDP socket
	QueueID     int          // XDP queue ID
}

// Packet data
type packet struct {
	IsUpdate    bool  // Whether the packet is a metadata update packet (true: yes, false: no)
	IsSwap      uint8 // Whether the packet is a metadata exchange packet (0: no, 1: initiator sends an exchange request to the recipient, 2: recipient responds to the initiator, data exchange completed)
	IsBroadcast uint8 // Whether the packet is a metadata broadcast packet (0: no, 1: yes) using unit8 is for ebpf program check packet type.

	// Node information
	Node     Node            // Node information in the heartbeat packet
	Infected map[string]bool // List of nodes already infected by this packet, the key is a string concatenated by Addr:Port, and the value determines whether the node has been infected (true: yes, false: no)

	// Metadata information
	Metadata  metadata // New metadata information, if the packet is a metadata update packet (isUpdate=true), then replace the original cluster metadata with newData
	SecretKey string   // Cluster key, if it doesn't match, reject processing this packet
}

// Metadata information
type metadata struct {
	Data   []byte // Metadata content
	Update int64  // Metadata version (update timestamp)
}

type nodeIPList struct {
	IPList []string `json:"IPList"`
}
