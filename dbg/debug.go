package dbg

import "fmt"

var verboseMode bool

func DebugPrintf(text string, a ...interface{}) {
	if verboseMode {
		fmt.Printf(text, a...)
	}
}

func DebugPrintln(text string) {
	if verboseMode {
		fmt.Println(text)
	}
}

func SetVerboseMode(v bool) {
	verboseMode = v
}
