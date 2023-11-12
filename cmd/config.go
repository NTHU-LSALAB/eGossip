package cmd

import (
	"sync"
	"sync/atomic"

	"github.com/asavie/xdp"
	bpf "github.com/kerwenwwer/xdp-gossip/bpf"
	common "github.com/kerwenwwer/xdp-gossip/common"
)

//var bpfLock sync.Mutex

// NodeList is a list of nodes
type NodeList struct {
	nodes   sync.Map // Collection of nodes (key is Node structure, value is the most recent second-level timestamp of node update)
	Amount  int      // Number of nodes to send synchronization information to at one time
	Cycle   int64    // Synchronization cycle (how many seconds to send list synchronization information to other nodes)
	Buffer  int      // UDP/TCP receive buffer size (determines how many requests the UDP/TCP listening service can process asynchronously)
	Size    int      // Maximum capacity of a single UDP/TCP heartbeat packet (in bytes)
	Timeout int64    // Expiry deletion limit for a single node (delete after how many seconds)

	SecretKey string // Cluster key, the keys of all nodes in the same cluster should be consistent

	localNode common.Node // Local node information

	Protocol   string // Network protocol used by the cluster connection, UDP or TCP, XDP(UDP based with ebpf feature) default is UDP
	ListenAddr string // Local UDP/TCP listening address, use this address to receive heartbeat packets from other nodes (usually 0.0.0.0 is sufficient)

	status atomic.Value // Status of local node list update (true: running normally, false: stop publishing heartbeat)

	IsPrint bool // Whether to print list synchronization information to the console

	metadata atomic.Value // Metadata, the metadata content of each node in the cluster is consistent, equivalent to the public data of the cluster (can store some common configuration information), can update the metadata content of each node through broadcasting

	Program *bpf.BpfObjects       // bpf program
	Xsk     *xdp.Socket           // xdp socket
	Counter *common.AtomicCounter // bpf program key counter
}
