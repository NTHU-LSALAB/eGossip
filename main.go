package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/kerwenwwer/xdp-gossip/cmd"
	"github.com/spf13/cobra"
)

var nodeName string
var linkName string
var protocol string

var rootCmd = &cobra.Command{
	Use:   "server",
	Short: "XDP Gossip Contorl Server",
	Long:  `A HTTP server for XDP Gossip control plane.`,
	Run: func(cmd *cobra.Command, args []string) {
		startServer()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func startServer() {
	fmt.Printf("---------- Starting XDP Gossip node --------\n")
	fmt.Printf("Node name: %s\n", nodeName)
	fmt.Printf("Protocol: %s\n", protocol)
	fmt.Printf("--------------------------------------------\n")

	// Default address
	address := "0.0.0.0"

	netInterface, err := net.InterfaceByName(linkName)
	if err != nil {
		log.Println("[[Control]: Get network device error. %v]", err)
		return
	}

	addrs, err := netInterface.Addrs()
	if err != nil {
		log.Println("[[Control]: Get address error. %v]", err)
		return
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		// print out IP address
		if ip.To4() != nil {
			address = ip.String()
		}
	}

	nodeList := cmd.NodeList{
		Protocol:  protocol, // The network protocol used to connect cluster nodes
		SecretKey: "test_key",
		IsPrint:   true,
	}

	nodeList.New(cmd.Node{
		Addr:        address,
		Port:        8000,
		Name:        nodeName,
		PrivateData: "test-data",
	})

	nodeList.Join()

	node := nodeList.Get()
	fmt.Println(node)

	// Set up the HTTP server
	http.HandleFunc("/set", nodeList.SetNodeHandler())
	http.HandleFunc("/list", nodeList.ListNodeHandler())
	http.HandleFunc("/stop", nodeList.StopNodeHandler())
	http.HandleFunc("/publish", nodeList.PublishHandler())
	http.HandleFunc("/metadata", nodeList.GetMetadataHandler())

	// Start the server
	log.Println("[[Control]: Starting http command server in TCP port 8000.]")
	http.ListenAndServe(":8000", nil)
}

func init() {
	rootCmd.Flags().StringVar(&nodeName, "name", "", "provide a node name")
	rootCmd.Flags().StringVar(&linkName, "link", "eth0", "provide a link name")
	rootCmd.Flags().StringVar(&protocol, "proto", "UDP", "provide a running mode")
}

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
