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

// Finds the group name based on a GID
func GetGroupnameFromGid(gid uint32) string {
	g, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	if err != nil {
		return fmt.Sprintf("GID %d", gid)
	}
	return g.Name
}

// Finds the name of a file from a pid and a fd
func GetFilePath(pid uint32, fd uint64) string {
	path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(path)
	if err != nil {
		return ":["
	}
	return target
}

// Obtains a syscall name given a char as code
func GetSyscallFromCode(b byte) string {
	switch b {
	case 'c':
		return "Clone"
	case 'f':
		return "Fork"
	case 'e':
		return "Execv"
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
