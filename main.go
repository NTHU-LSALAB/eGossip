package main

import (
	"fmt" // Standard library imports are grouped together.
	"log" // Logging is crucial for both debugging and runtime monitoring.
	"net"
	"net/http"

	// Networking package for handling sockets.
	// HTTP server functionalities.
	"os" // OS-level operations like file handling.

	// Third-party imports are grouped separately.
	// This includes all external packages not part of the standard library.
	// Keeping standard and third-party imports separate improves readability.
	"github.com/kerwenwwer/eGossip/modules/helper"
	nd "github.com/kerwenwwer/eGossip/modules/nodeList"
	"github.com/kerwenwwer/eGossip/pkg/bpf"
	"github.com/kerwenwwer/eGossip/pkg/common"
	logger "github.com/kerwenwwer/eGossip/pkg/logger"
	"github.com/spf13/cobra" // Cobra package for CLI interactions.
)

// Constants for default configuration values.
const (
	DefaultLinkName = "eth0"
	DefaultProtocol = "UDP"
	DefaultPort     = "8000" // Ports are strings in Go's http package.
)

// Config struct to hold all configuration needed across the application.
type Config struct {
	NodeName string
	LinkName string
	Protocol string
	Debug    bool
}

func main() {
	config := Config{} // Instantiate the config struct to hold runtime configurations.

	// Initialize the root command.
	rootCmd := &cobra.Command{
		Use:   "eGossip",
		Short: "Runs the esGossip application as either server or client.",
	}

	// Server command configuration.
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Starts the eGossip Server",
		Long:  `Initializes and runs the eGossip control server for managing the gossip protocol.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := startServer(config); err != nil {
				log.Fatalf("Failed to start server: %v", err)
			}
		},
	}
	// Flags for the server command.
	serverCmd.Flags().StringVar(&config.NodeName, "name", "", "Node name for identifying in the network.")
	serverCmd.Flags().StringVar(&config.LinkName, "link", DefaultLinkName, "Network link interface name.")
	serverCmd.Flags().StringVar(&config.Protocol, "proto", DefaultProtocol, "Networking protocol (UDP/TC/XDP).")
	serverCmd.Flags().BoolVar(&config.Debug, "debug", false, "Enables debug mode for verbose logging.")

	// Client command configuration.
	dummyClientCmd := &cobra.Command{
		Use:   "client",
		Short: "Starts the eGossip Dummy Client",
		Long:  `Launches a UDP client for testing the eGossip communication.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := startDummyClient(); err != nil {
				log.Fatalf("Error starting the client: %v", err)
			}
		},
	}

	// Add server and client commands to root.
	rootCmd.AddCommand(serverCmd, dummyClientCmd)

	// Execute the root command.
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}

// startServer initializes the eGossip server with the provided configuration.
func startServer(cfg Config) error {
	log.Println("---------- Starting eGossip node ----------")
	log.Printf("Node name: %s", cfg.NodeName)
	log.Printf("Protocol: %s", cfg.Protocol)
	log.Printf("DEBUG: %t", cfg.Debug)
	log.Println("---------------------------------------------")

	address, err := findNodeAddress(cfg.LinkName)
	if err != nil {
		return fmt.Errorf("[Init]: Failed to find node address: %w", err)
	}

	nodeList, err := initializeNodeList(cfg, address)
	if err != nil {
		return fmt.Errorf("[Init]: Failed to initialize node list: %w", err)
	}

	nodeList.Logger = logger.NewLogger(&logger.LoggerConfig{Development: true})

	nodeList.Join() // Join the network.

	http.HandleFunc("/set", nodeList.SetNodeHandler())
	http.HandleFunc("/list", nodeList.ListNodeHandler())
	http.HandleFunc("/stop", nodeList.StopNodeHandler())
	http.HandleFunc("/publish", nodeList.PublishHandler())
	http.HandleFunc("/metadata", nodeList.GetMetadataHandler())

	log.Printf("[Control]: Starting HTTP command server on TCP port 8000.")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		return fmt.Errorf("[Control]: ListenAndServe failed: %w", err)
	}

	return nil
}

func findNodeAddress(linkName string) (string, error) {
	netInterface, err := net.InterfaceByName(linkName)
	if err != nil {
		return "", fmt.Errorf("get network device error: %w", err)
	}

	addrs, err := netInterface.Addrs()
	if err != nil {
		return "", fmt.Errorf("get address error: %w", err)
	}

	for _, addr := range addrs {
		ip := getIPFromAddr(addr)
		if ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}

	return "0.0.0.0", nil // Default address if no IPv4 address found.
}

func getIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

func initializeNodeList(cfg Config, address string) (nd.NodeList, error) {
	nodeList := nd.NodeList{
		Protocol:  cfg.Protocol,
		SecretKey: "test_key", // Assume this is a placeholder value.
		IsPrint:   cfg.Debug,
	}

	if cfg.Debug {
		file, err := os.Create("debug_output.txt")
		if err != nil {
			return nd.NodeList{}, fmt.Errorf("[Init.]: Failed to create debug output file: %w", err)
		}
		defer file.Close()

		os.Stdout = file // Consider the implications of redirecting os.Stdout globally.
	}

	if cfg.Protocol == "XDP" {
		if err := loadAndAssignBPFProgram(&nodeList, cfg.LinkName, cfg.Debug, 1); err != nil {
			return nd.NodeList{}, err
		}
	} else if cfg.Protocol == "TC" {
		if err := loadAndAssignBPFProgram(&nodeList, cfg.LinkName, cfg.Debug, 0); err != nil {
			return nd.NodeList{}, err
		}
	}

	if err := configureNodeList(&nodeList, cfg, address); err != nil {
		return nd.NodeList{}, err
	}

	return nodeList, nil
}

func loadAndAssignBPFProgram(nodeList *nd.NodeList, linkName string, debug bool, mode int) error {
	obj, err := bpf.LoadObjects()
	if err != nil {
		return fmt.Errorf("[Init.]: Failed to load BPF objects: %w", err)
	}

	nodeList.Program = obj
	l, xsk := helper.ProgramHandler(linkName, obj, debug, mode)
	if l != nil {
		defer l.Close()
	}
	nodeList.Xsk = xsk
	return nil
}

func configureNodeList(nodeList *nd.NodeList, cfg Config, address string) error {
	macAddress, err := common.GetMACAddressByInterfaceName(cfg.LinkName)
	if err != nil {
		return fmt.Errorf("[Init.]: Get MAC address error: %w", err)
	}

	gatewayMAC, err := common.FindGatewayMAC(cfg.LinkName)
	if err != nil {
		return fmt.Errorf("[Init.]: Get gateway MAC address error: %w", err)
	}

	nodeList.GatewayMAC = gatewayMAC.String()

	nodeList.New(common.Node{
		Addr:        address,
		Port:        8000, // Consider making this configurable as well.
		Mac:         macAddress,
		Name:        cfg.NodeName,
		LinkName:    cfg.LinkName,
		PrivateData: "test-data", // Placeholder, consider making this configurable or dynamically generated.
	})

	return nil
}

func startDummyClient() error {
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

	log.Println("[Control]: Client is listening on UDP port 8000")

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
