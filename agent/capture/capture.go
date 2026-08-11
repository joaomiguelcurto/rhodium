// capture reads packets off a network interface using npcap and figures out
// how many bytes each local process is pushing around.
package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"rhodium/agent/procmap"
)

// hardcoded to my Realtek adapter for now, the real network interface
// will make it selectable in the future.
const deviceName = `\Device\NPF_{B5A77F7B-8C08-473E-BF99-58201EC12685}`

// state holds everything the capture loop needs to share across goroutines:
// the current port table snapshot, and a running byte tally per PID.
// mu protects both, since the refresh timer and the packet loop touch
// them from different goroutines.
type state struct {
	mu        sync.Mutex
	portTable map[uint16]uint32
	tally     map[uint32]int64 // pid -> total bytes seen
}

// Opens the live capture handle, does an initial PortTable() fetch so we are not empty-handed for the first few packets,
// kicks off two background goroutines (refreshLoop, summaryLoop), then loops forever reading packets and handing each one to handlePacket.
func Run() error {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening device: %w", err)
	}
	defer handle.Close()

	st := &state{tally: make(map[uint32]int64)}

	// grab an initial port table before we start reading packets, so the
	// very first packets have something to match against.
	table, err := procmap.PortTable()
	if err != nil {
		return fmt.Errorf("initial port table: %w", err)
	}
	st.portTable = table

	// refresh the port table every second in the background instead of
	// rebuilding it per-packet. connections come and go, so this needs to
	// stay reasonably fresh, but once a second is plenty for a dashboard.
	go refreshLoop(st)

	// print a summary every 2 seconds instead of spamming per-packet.
	go summaryLoop(st)

	fmt.Println("capturing... press ctrl+c to stop")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(st, packet)
	}

	return nil
}

// refreshLoop keeps the port table reasonably up to date without doing it
// on every single packet.
func refreshLoop(st *state) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		table, err := procmap.PortTable()
		if err != nil {
			continue // just keep using the stale table, not worth crashing over
		}
		st.mu.Lock()
		st.portTable = table
		st.mu.Unlock()
	}
}

// summaryLoop periodically prints per-process totals and resets the tally,
// so numbers reflect "bytes in the last 2 seconds" rather than growing
// forever.
func summaryLoop(st *state) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		st.mu.Lock()
		fmt.Println("--- last 2s ---")
		for pid, bytes := range st.tally {
			name, err := procmap.ProcessName(pid)
			if err != nil {
				name = "unknown"
			}
			fmt.Printf("%s (pid %d): %d bytes\n", name, pid, bytes)
		}
		st.tally = make(map[uint32]int64) // reset for the next window
		st.mu.Unlock()
	}
}

// handlePacket looks up which PID a packet belongs to using the cached
// port table (no syscall per packet anymore) and adds its size to that
// PID's running tally.
func handlePacket(st *state, packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	size := int64(len(packet.Data()))

	st.mu.Lock()
	defer st.mu.Unlock()

	if pid, ok := st.portTable[uint16(tcp.SrcPort)]; ok {
		st.tally[pid] += size
		return
	}
	if pid, ok := st.portTable[uint16(tcp.DstPort)]; ok {
		st.tally[pid] += size
		return
	}
	// neither port is local, ignore
}

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
