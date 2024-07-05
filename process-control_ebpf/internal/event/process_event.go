package event

import (
	"encoding/binary"

	"example.com/user-activity/utils"
)

type Action struct {
	Pid        uint32
	User       string
	ActionName string
}

func UnmarshallAction(marshd []byte) Action {
	//utils.PrintBytesHex(marshd)

	action := Action{}

	action.Pid = binary.LittleEndian.Uint32(marshd[0:4])
	uid := binary.LittleEndian.Uint32(marshd[4:8])
	action.User = utils.GetUsernameFromUid(uid)
	action.ActionName = string(marshd[8:24])

	return action
}
