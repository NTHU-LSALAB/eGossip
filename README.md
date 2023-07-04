# XDP Gossip

## A Gossip protocol toolkit based on XDP

### Basic Gossip API is from [PekoNode](https://github.com/dpwgc/pekonode/tree/master)

![MIT](https://img.shields.io/static/v1?label=LICENSE&message=MIT&color=red)
![Go](https://img.shields.io/static/v1?label=Go&message=v1.19&color=blue)
[![github](https://img.shields.io/static/v1?label=Github&message=pekonode&color=blue)](https://github.com/kerwenwwer/xdp-gossip)

***
### Implement function
##### Cluster node list sharing
* Synchronize the list of cluster nodes through rumor propagation `NodeList` (Each node will eventually store a complete list of nodes that can be used in service registration discovery scenarios)
##### Cluster metadata information sharing
* Publishing cluster metadata information through rumor spreading `Metadata` (The public data of the cluster, the local metadata information of each node is eventually consistent, and the storage content can be customized, such as storing some public configuration information, acting as a configuration center), The metadata verification and error correction function of each node of the cluster is realized through data exchange.
##### TCP or UDP protocol can be used to realize bottom communication interaction
* Customize the underlying communication protocol through the `NodeList - Protocol` field. UDP is used by default. If you want to pursue high reliability, you can use TCP.
##### Custom configuration
* The node list `NodeList` list provides a series of parameters for users to customize and configure. Users can use the default parameters, or fill in the parameters according to their needs.
***

### Implementation principle
##### `NodeList` Node list information synchronization
* Each node has a local node list NodeList.
* The background synchronization protocol of each node periodically encapsulates the node information into heartbeat data packets, and broadcasts it to some uninfected nodes in the cluster.
* After other nodes receive the heartbeat packet, they update their own local node list NodeList, and then broadcast the heartbeat packet to some uninfected nodes in the cluster.
* Repeat the previous broadcast step (rumor propagation method) until all nodes are infected, and this heartbeat infection ends.
* If there is a node in the local node list NodeList that has not sent the heartbeat update after timeout, delete the data of the timeout node.

![](img/1.png)

##### `Metadata` Metadata information synchronization
* After a node calls the Publish() function to publish new metadata, the new data will spread to each node and then overwrite their local metadata information.
* Each node will periodically select a random node for metadata exchange check operation. If the metadata on a node is found to be old, it will be overwritten (anti-entropy propagation method).
* When a new node joins the cluster, the node will obtain the latest cluster metadata information through the data exchange function.

![](img/2.png)

***

### Import package
* Goland terminal input
```
go get github.com/dpwgc/pekonode
```
* Introduced in the program
```
import "github.com/dpwgc/pekonode"
```

***
### Instructions
* Configure the local node list `nodeList`
```
nodeList := pekonode.NodeList{
        IsPrint:   true, // Whether to print the list synchronization information to the console
}
```

* Initialize the local node list and set local node information `0.0.0.0:8000`
```
nodeList.New(pekonode.Node{
	Addr: "0.0.0.0",  // IP address of the local node, please fill in the public network IP in the public network environment
	Port: 8000,       // Local node port number (Listen to the information sent by other nodes through this port)
})
```
* Add other node information `0.0.0.0:9999` to the local node list
```
// 0.0.0.0:9999 is a node that has been started in the cluster
nodeList.Set(pekonode.Node{
	Addr: "0.0.0.0",
	Port: 9999,
})
```
* Add the node  `0.0.0.0:8000`  to the Gossip cluster (start the heartbeat broadcast and listening coroutine in the background)
```
// After joining the cluster, node 0.0.0.0:8000 will establish contact with node 0.0.0:9999
nodeList.Join()
```
* Get local node list
```
list := nodeList.Get()

fmt.Println(list)

// list: 0.0.0.0:8000, 0.0.0.0:9999
```
* Node stops publishing heartbeats
```
nodeList.Stop()
```
* Node restarts to publish heartbeats
```
nodeList.Start()
```
* Publish new metadata information in the cluster
```
nodeList.Publish([]byte("test metadata"))
```
* Get local metadata information
```
metadata := nodeList.Read()

fmt.Println(string(metadata))
```
***

### Simple usage example
#### Start a node
```
package main

import (
	"github.com/dpwgc/pekonode"
	"time"
)

// Simple example, start a node
func main()  {

	// Configure the local node list parameters for this node
	nodeList := pekonode.NodeList{
		IsPrint:    true, // Whether to output log information in the console, if not filled, the default is false
	}

	// Create a local node list and pass in local node information
	nodeList.New(pekonode.Node{
		Addr: "0.0.0.0",            // IP address of the local node, please fill in the public network IP in the public network environment
		Port: 8000,                 // Local node port number
		Name: "Test",               // Node name, fill in custom
		PrivateData: "test-data",   // Node private data content, customize
	})

	// Add new node information to the local node list, you can add multiple nodes, the local node will synchronize information with these new nodes.
	// If the first node in the cluster is started, the Set() addition operation can be omitted.
	nodeList.Set(pekonode.Node{
		Addr: "0.0.0.0",
		Port: 9999,
		Name: "Hello",
		PrivateData: "test-data",
	})
	nodeList.Set(pekonode.Node{
		Addr: "0.0.0.0",
		Port: 7777,
		Name: "Hi",
		PrivateData: "test-data",
	})

	// Add the node to the Gossip cluster (start the heartbeat broadcast and listening coroutine in the background)
	nodeList.Join()
	
	// Get local node list
	list := nodeList.Get()
	// Print node list
	fmt.Println(list)
	
	// Publish new metadata information in the cluster
	nodeList.Publish([]byte("test metadata"))
	
	// Read local metadata information
	metadata := nodeList.Read()
	// Print metadata information
	fmt.Println(string(metadata))
	
	// Because the work of heartbeat broadcasting is performed in the background coroutine, the main coroutine cannot be closed after calling the Join function, otherwise the program will exit directly.
	// Infinite loop
	for {
		time.Sleep(10*time.Second)
	}
}
```

***

### Complete usage example
Test files: Under `/test` directory
* test
  * tcp `TCP cluster connection test`
  * udp `UDP cluster connection test`

***
### Configuration description
```
// NodeList
type NodeList struct {
	nodes   sync.Map        // Node set (key is the Node structure, value is the second-level timestamp of the latest update of the node)
	Amount  int             // Fan-out, How many nodes to send synchronization information to each time
	Cycle   int64           // Synchronization time period (how many seconds to send list synchronization information to other nodes)
	Buffer  int             // UDP/TCP receive buffer size (determines how many requests the UDP/TCP listening service can handle asynchronously)
	Size    int             // The maximum capacity of a single UDP/TCP heartbeat data packet, the default is 16k, if you need to synchronize larger metadata, please increase it yourself (unit: bytes)
	Timeout int64           // Expired deletion limit for a single node (how many seconds to delete)
	SecretKey string        // Cluster secret key, the keys of each node in the same cluster should be consistent
	localNode Node          // local node information
	Protocol string         // Network protocol used for cluster connection, UDP or TCP, default UDP
	ListenAddr string       // Local UDP/TCP listening address, use this listening address to receive heartbeat packets from other nodes (generally fill in 0.0.0.0)
	status atomic.Value     // Local node list update status (true: normal operation, false: stop publishing heartbeats)
	IsPrint bool            // Whether to print the list synchronization information to the console
	metadata atomic.Value   // Metadata, equivalent to the public data of the cluster (can store some public configuration information)
}

// Node
type Node struct {
	Addr string             // Node IP address (in the public network environment, fill in the public network IP)
	Port int                // The port number
	Name string             // Node name (custom)
	PrivateData string      // Node private data content (custom)
}
```

***
### Console print information
#### When the IsPrint parameter of NodeList is set to true, the program will print out the running information on the console.
##### When the node joins the cluster, print:
```
2022-05-19 14:51:23 [[Join]: {0.0.0.0 8000 A-server A}]
```
* Indicates that node 0.0.0.0:8000 joins the cluster

##### When a node publishes a heartbeat, print:
```
2022-05-19 14:52:23 [[Listen]: 0.0.0.0:8000 / [Node list]: [{0.0.0.0 8000 A-server A} {0.0.0.0 8001 B-server B}]]
```
* Listen indicates the address and port of the local UDP listening service, and Node list indicates the current local node list.

##### When the node heartbeat broadcast is paused, print:
```
2022-05-19 14:52:06 [[Stop]: {0.0.0.0 8002 C-server C}]
```
* Indicates that node 0.0.0.0:8002 stops broadcasting heartbeat packets.

##### When restarting the node heartbeat broadcast, print:
```
2022-05-19 14:52:36 [[Start]: {0.0.0.0 8002 C-server C}]
```
* Indicates that node 0.0.0.0:8002 restarts broadcasting heartbeat packets.

##### When metadata is exchanged between two nodes, print:
```
2022-05-20 13:12:26 [[Swap Request]: 0.0.0.0:8002 -> 0.0.0.0:8000]
2022-05-20 13:12:26 [[Swap Response]: 0.0.0.0:8002 <- 0.0.0.0:8000]
```
* The 8002 node initiates a data exchange request to the 8000 node.
* The 8000 node responds to the exchange request of the 8002 node, and the data exchange work is completed.


***

### Project structure
* pekonode
    * test `Test files`
    * config.go `Configure template`
    * opt.go `Provided to external series operation functions`
    * print.go `Console output`
    * sync.go `Cluster synchronization service`
    * net.go `network service`
    * udp.go `UDP sending and receiving service`
    * tcp.go `TCP sending and receiving service`
    * md5.go `MD5 key generation`