package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/kerwenwwer/xdp-gossip/bpf"
	"github.com/kerwenwwer/xdp-gossip/cmd"
	"github.com/kerwenwwer/xdp-gossip/common"
	"github.com/spf13/cobra"
)

var nodeName string
var linkName string
var protocol string
var isServer bool
var debug bool = false

func startServer() {
	fmt.Printf("---------- Starting XDP Gossip node --------\n")
	fmt.Printf("Node name: %s\n", nodeName)
	fmt.Printf("Protocol: %s\n", protocol)
	fmt.Printf("DEBUG: %d\n", debug)
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
	}

	if debug {
		nodeList.IsPrint = true
	} else {
		nodeList.IsPrint = false
	}

	/* Load BPF program */
	if nodeList.Protocol == "XDP" {
		obj, err := bpf.LoadObjects()
		if err != nil {
			log.Fatalf("[Error]:", "Failed to load objects: %v", err)
		}

		nodeList.Program = obj

		l, xsk := cmd.ProgramHandler(linkName, obj, debug)
		defer l.Close()
		nodeList.Xsk = xsk
	}

	mac_address, err := common.GetMACAddressByInterfaceName(linkName)
	if err != nil {
		log.Fatal("[[Control]: Get MAC address error. %v]", err)
	}

	nodeList.New(common.Node{
		Addr:        address,
		Port:        8000,
		Mac:         mac_address,
		Name:        nodeName,
		LinkName:    linkName,
		PrivateData: "test-data",
	})

	nodeList.Join()

	// Set up the HTTP server
	http.HandleFunc("/set", nodeList.SetNodeHandler())
	http.HandleFunc("/list", nodeList.ListNodeHandler())
	http.HandleFunc("/stop", nodeList.StopNodeHandler())
	http.HandleFunc("/publish", nodeList.PublishHandler())
	http.HandleFunc("/metadata", nodeList.GetMetadataHandler())

	// Start the profile server
	if debug {
		cmd.NewProfileHttpServer(":9000")
	}
	//defer profile.Start().Stop()

	// Start the server
	log.Println("[[Control]: Starting http command server in TCP port 8000.]")
	err = http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Panicln("[[Control]: ListenAndServe: ", err)
	}
}

func startClient() error {
	// Code for starting UDP listener on port 8000
	addr := net.UDPAddr{
		Port: 8000,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	log.Println("Client is listening on UDP port 8000")

	// Buffer for reading incoming packets
	buffer := make([]byte, 1024)
	// Add code to handle incoming messages, etc.
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v\n", err)
			continue
		}

		// Print the received message
		message := string(buffer[:n])

		if message[8] == '1' {
			log.Printf("Received %d bytes from %v: %s\n", n, remoteAddr, message)
		}

		// Add additional code to handle the message if necessary
	}
}

var rootCmd = &cobra.Command{
	Use:   "xdp-gossip",
	Short: "XDP Gossip Application",
	Long:  `This application runs either as an XDP Gossip server or client.`,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "XDP Gossip Contorl Server",
	Long:  `A HTTP server for XDP Gossip control plane.`,
	Run: func(coCmd *cobra.Command, args []string) {
		startServer()
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "XDP Gossip UDP Client",
	Long:  `A client for testing XDP Gossip communication.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := startClient(); err != nil {
			log.Fatalf("Error starting client: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)

	serverCmd.Flags().StringVar(&nodeName, "name", "", "provide a node name.")
	serverCmd.Flags().StringVar(&linkName, "link", "eth0", "provide a link name.")
	serverCmd.Flags().StringVar(&protocol, "proto", "UDP", "provide a running mode.")
	serverCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug mode, open print and profile.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
