// procmap figures out which process owns a given local port
// by using iphlpapi.dll (Windows network library)
package procmap

import (
	"fmt"
	"syscall"
	"unsafe"
)

// loads the DLL and handles the one function we need,
// GetExtendedTcpTable, "Lazy" means it doesnt actually get used
// until we call it the first time
var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// mirrors MIB_TCPROW_OWNER_PID from the Windows API, byte for byte.
// struct docs: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
// function docs: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

const (
	tcpTableOwnerPidAll   = 5   // table format that includes PIDs, see TCP_TABLE_CLASS enum
	afInet                = 2   // IPv4, see AF_INET
	errInsufficientBuffer = 122 // expected on the first call, not a real error
)

// PortOwner returns the PID currently holding the given local port.
func PortOwner(localPort uint16) (uint32, error) {
	// classic Windows two-call dance: first call just asks "how big should my buffer be?"
	// pattern explained here: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#remarks
	var size uint32
	ret, _, _ := procGetExtTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(afInet),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if ret != 0 && ret != errInsufficientBuffer {
		return 0, fmt.Errorf("GetExtendedTcpTable size query failed: code %d", ret)
	}

	// now we know the size, so allocate and ask for real
	buf := make([]byte, size)
	ret, _, _ = procGetExtTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(afInet),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable fetch failed: code %d", ret)
	}

	return parseTCPTable(buf, localPort)
}

// PortTable returns a snapshot of every local port currently mapped to
// its owning PID. Building this once and reusing it for a short window is
// much cheaper than calling PortOwner per-packet, which rebuilds the whole
// table from scratch every single time.
func PortTable() (map[uint16]uint32, error) {
	var size uint32
	ret, _, _ := procGetExtTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(afInet),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if ret != 0 && ret != errInsufficientBuffer {
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: code %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(afInet),
		uintptr(tcpTableOwnerPidAll),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable fetch failed: code %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[0])) + 4

	table := make(map[uint16]uint32, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))

		lo := byte(row.LocalPort)
		hi := byte(row.LocalPort >> 8)
		port := uint16(lo)<<8 | uint16(hi)

		table[port] = row.OwningPid
	}

	return table, nil
}

// parseTCPTable guides the raw byte buffer received from Windows API
// row by row, manually reading memory offsets, looking for the row matching our port.
func parseTCPTable(buf []byte, localPort uint16) (uint32, error) {
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[0])) + 4

	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))

		// port comes back big-endian, gotta flip it to compare normally
		// (this is just ntohs, Windows doesn't give us that helper directly here)
		lo := byte(row.LocalPort)      // lowest byte of the DWORD
		hi := byte(row.LocalPort >> 8) // second byte of the DWORD
		rowPort := uint16(lo)<<8 | uint16(hi)

		if rowPort == localPort {
			return row.OwningPid, nil
		}
	}

	return 0, fmt.Errorf("no process found owning port %d", localPort)
}
