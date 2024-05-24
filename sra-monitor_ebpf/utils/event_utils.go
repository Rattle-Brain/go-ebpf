package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Finds the username of a certain UID
func GetUsernameFromUid(uid uint32) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return fmt.Sprintf("UID %d", uid)
	}
	return u.Username
}

// Finds the name of a file from a pid and a fd
func GetFilePath(pid uint32, fd uint64) string {
	path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Sprintf("FD %d", fd)
	}
	return target
}

// Obtains a syscall name given a char as code
func GetSyscallFromCode(b byte) string {
	switch b {
	case 'o':
		return "Syscall Openat"
	case 'r':
		return "Syscall Read"
	case 'w':
		return "Syscall Write"
	default:
		return "None"
	}
}

// DEBUG ONLY Prints a raw sample as hex and aborts the execution
func PrintBytesHex(rawsample []byte) {

	fmt.Print("[")
	for i := 0; i < len(rawsample); i++ {
		if i%4 == 0 {
			fmt.Println()
		}
		if i == len(rawsample) {
			fmt.Printf("0x%x", rawsample[i])
		}
		fmt.Printf("0x%x, ", rawsample[i])
	}
	fmt.Print("]\n")
	os.Exit(1)
}
