package action

type Action struct {
	User string
	Name string
}

func UnmarshallAction(marshd []byte) Action {
	return Action{}
}
