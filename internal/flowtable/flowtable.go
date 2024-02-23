package flowtable

/*
A flow table is a data structure used to store and manage
information about network flows and s often used in packet processing pipelines to
efficiently match incoming packets against existing flow entries and take
appropriate actions based on the matching results.

Given the information above, we can see why would we use a flowtable to store
information. Especifically, we want to store info in a Map structure, with a
hash as a key and the timestamp of a packet as the value.
*/
import (
	"sync"
	"time"

	"go.mod/dbg"
	"go.mod/internal/timer"
)

type FlowTable struct {
	Ticker *time.Ticker
	sync.Map
}

// "Creates" a new FlowTable
func NewFT() *FlowTable {
	return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
}

func (ft *FlowTable) Add(hash, ts uint64) {
	ft.Store(hash, ts)
}

func (ft *FlowTable) Get(hash uint64) (uint64, bool) {
	val, ok := ft.Load(hash)

	// If the key is not in the map, return this (0, false)
	if !ok {
		dbg.DebugPrintf("This hash (%v) is not in flow table\n", hash)
		return 0, ok
	}
	return val.(uint64), ok
}

func (ft *FlowTable) Remove(hash uint64) {
	_, isFound := ft.Get(hash)

	if isFound {
		ft.Delete(hash)
	} else {
		dbg.DebugPrintf("hash %v is not in flow table\n", hash)
	}
}

// This function is not mine. I'm still trying to understand it
// Basically it removes any entry older than 10s from the table.
func (ft *FlowTable) Flush() {
	now := timer.GetNanosecSinceBoot()

	ft.Range(func(hash, timestamp interface{}) bool {
		if (now-timestamp.(uint64))/1000000 > 10000 {
			dbg.DebugPrintf("Removing old entry from flow table: %v\n", hash)

			ft.Remove(hash.(uint64))

			return true
		}
		return false
	})
}
