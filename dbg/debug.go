package dbg

import "fmt"

/*
	This section is easy to understand. It's just an interface that activates or
	deactivates certain prints with the value "verboseMode". A way to keep the code
	a bit cleaner.
*/

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
