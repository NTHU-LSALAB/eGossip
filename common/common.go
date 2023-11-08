package common

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"
)

// Node represents a node
type Node struct {
	Addr        string `json:"Addr"`        // Node IP address (fill in public IP in public network environment)
	Port        int    `json:"Port"`        // Port number
	Mac         string `json:"Mac"`         // Node MAC address
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
type Packet struct {
	Type   uint8  // 0 not used 1: heartbeat packet, 2: initiator sends an exchange request to the recipient, 3: recipient responds to the initiator, data exchange completed
	Count  uint16 // Broadcast packet count (0-64)
	Mapkey uint16 // Map key
	// Metadata information
	Metadata Metadata // New metadata information, if the packet is a metadata update packet (isUpdate=true), then replace the original cluster metadata with newData

	// Node information
	Node     Node            // Node information in the heartbeat packet
	Infected map[string]bool // List of nodes already infected by this packet, the key is a string concatenated by Addr:Port, and the value determines whether the node has been infected (true: yes, false: no)
	IsUpdate bool            // Whether it is a metadata update packet (0: no, 1: yes)

	SecretKey string // Cluster key, if it doesn't match, reject processing this packet
	CountStr  string
}

// Metadata information
type Metadata struct {
	Size   int    // Metadata size
	Update int64  // Metadata version (update timestamp)
	Data   []byte // Metadata content
}

type AtomicCounter struct {
	val int32
}

func NewAtomicCounter() *AtomicCounter {
	return &AtomicCounter{val: 100}
}

func (ac *AtomicCounter) Next() uint16 {
	// Increment the current value and get the new value
	newVal := atomic.AddInt32(&ac.val, 1)

	// If the new value exceeds 999, wrap it around to 100.
	// Use CAS (Compare-And-Swap) to ensure atomicity.
	for newVal > 999 {
		if atomic.CompareAndSwapInt32(&ac.val, newVal, 100) {
			return 100
		}
		newVal = atomic.AddInt32(&ac.val, 1)
	}
	return uint16(newVal)
}

// IpToUint32 converts IP to uint32
func IpToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Failed to parse IP: %s", ipStr)
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip)
}

func Uint32ToIp(ipInt uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ipInt&0xFF,
		(ipInt>>8)&0xFF,
		(ipInt>>16)&0xFF,
		(ipInt>>24)&0xFF)
}

func MacStringToInt8Array(macStr string) [6]int8 {
	var macInt8 [6]int8
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		log.Fatalf("Failed to parse MAC: %s", macStr)
		return macInt8
	}

	// net.HardwareAddr is a slice of uint8, need to convert it to [6]int8
	for i, val := range hwAddr {
		macInt8[i] = int8(val)
	}

	return macInt8
}

func GetMACAddressByInterfaceName(interfaceName string) (string, error) {
	interfaceObj, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}

	mac := interfaceObj.HardwareAddr.String()
	return mac, nil
}
