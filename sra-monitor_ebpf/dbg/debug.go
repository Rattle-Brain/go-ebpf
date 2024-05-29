package dbg

import "fmt"

var verbose bool
var extraVerbose bool

func DebugPrintf(text string, a ...interface{}) {
	if verbose {
		fmt.Printf(text, a...)
	}
}

func DebugPrintln(text string) {
	if verbose {
		fmt.Println(text)
	}
}

func DebugPrintfExtra(text string, a ...interface{}) {
	if extraVerbose {
		fmt.Printf(text, a...)
	}
}

func DebugPrintlnExtra(text string) {
	if extraVerbose {
		fmt.Println(text)
	}
}

func SetVerboseMode(v bool) {
	verbose = v
}

func SetExtraVerboseMode(v bool) {
	if v {
		verbose = v
	}
	extraVerbose = v
}
