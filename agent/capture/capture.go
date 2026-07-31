// capture reads packets off a network interface using npcap and figures out
// how many bytes each local process is pushing around.
package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"rhodium/agent/procmap"
)

// ListDevices prints every network interface npcap can see, so we can
// figure out which one to actually capture on.
func ListDevices() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("finding devices: %w", err)
	}

	for _, d := range devices {
		fmt.Printf("name: %s\n", d.Name)
		fmt.Printf("  desc: %s\n", d.Description)
		for _, addr := range d.Addresses {
			fmt.Printf("  addr: %s\n", addr.IP)
		}
	}

	return nil
}

// deviceName is hardcoded for now, we will make this configurable later.
const deviceName = `\Device\NPF_{B5A77F7B-8C08-473E-BF99-58201EC12685}`

// Run opens a live capture on the configured device and prints basic info
// about each packet it sees. This is just a proof of life, real parsing
// comes next.
func Run() error {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening device: %w", err)
	}
	defer handle.Close()

	fmt.Println("capturing... press ctrl+c to stop")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		info, ok := parsePacket(packet)
		if !ok {
			continue // not a TCP/IP packet we care about, e.g. ARP, skip it
		}
		fmt.Printf("%s (pid %d), %d bytes\n", info.Name, info.PID, info.Size)
	}

	return nil
}

// packetInfo is the bit of data we actually care about from each packet,
// now attributed to an actual process.
type packetInfo struct {
	PID  uint32
	Name string
	Size int
}

// parsePacket figures out which local port this packet belongs to (trying
// both source and dest, since we don't know direction ahead of time), then
// asks procmap which process owns that port.
func parsePacket(packet gopacket.Packet) (packetInfo, bool) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return packetInfo{}, false
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	size := len(packet.Data())

	pid, err := procmap.PortOwner(uint16(tcp.SrcPort))
	if err != nil {
		pid, err = procmap.PortOwner(uint16(tcp.DstPort))
		if err != nil {
			return packetInfo{}, false
		}
	}

	// name lookup can fail too, e.g. process exited between the port
	// lookup and now, don't throw the packet away just for that, fall
	// back to "unknown" instead
	name, err := procmap.ProcessName(pid)
	if err != nil {
		name = "unknown"
	}

	return packetInfo{PID: pid, Name: name, Size: size}, true
}
