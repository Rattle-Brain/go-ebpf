package event

// This struct defines the information of a process event
// Such as PPID, or Action (clone, exec, fork)
type Event struct {
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	Comm       string
	ParentComm string
	Action     string
}

func UnmarshallEvent(marshd []byte) Event {
	//utils.PrintBytesHex(marshd)

	evt := Event{}

	// TODO: Unmarshall binary to struct

	return evt
}
