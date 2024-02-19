package clsact

import "github.com/vishvananda/netlink"

/*
This ClsAct is necessary to create since the
VishVananda netlink interface for go has not
implemented the ClsAct Qdisc.
*/
type ClsAct struct {
	attrs *netlink.QdiscAttrs
}

func NewClsAct(attrs *netlink.QdiscAttrs) *ClsAct {
	return &ClsAct{attrs: attrs}
}

func (clsact *ClsAct) Attrs() *netlink.QdiscAttrs {
	return clsact.attrs
}

func (qdisc *ClsAct) Type() string {
	return "clsact"
}
