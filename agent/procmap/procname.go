// procname figures out, given a PID,
// what is the process name
package procmap

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// loads the DLL and handles the functions we need,
// "Lazy" means it doesnt actually get used
// until we call it the first time
var (
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
)

const processQueryLimitedInformation = 0x1000

// ProcessName returns just the executable name (e.g. "chrome.exe") for a
// given PID. Needs the process to still be alive when we call this, PIDs
// get reused by Windows once a process exits, so don't cache this forever.
// docs: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
func ProcessName(pid uint32) (string, error) {
	handle, _, _ := procOpenProcess.Call(
		uintptr(processQueryLimitedInformation),
		0, // bInheritHandle: false
		uintptr(pid),
	)
	if handle == 0 {
		return "", fmt.Errorf("opening process %d", pid)
	}
	defer procCloseHandle.Call(handle)

	buf := make([]uint16, 260) // MAX_PATH
	size := uint32(len(buf))

	ret, _, _ := procQueryFullProcessImageName.Call(
		handle,
		0, // dwFlags: 0 = win32 path format
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", fmt.Errorf("querying process %d", pid)
	}

	fullPath := syscall.UTF16ToString(buf[:size])
	return filepath.Base(fullPath), nil
}
