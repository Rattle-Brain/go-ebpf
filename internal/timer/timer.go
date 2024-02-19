package timer

import (
	"log"
	"time"

	"golang.org/x/sys/unix"
)

/*
We want to be able to precisely timestamp packets from the User Space.
However, we cannot do that since we can't access the eBPF helper fucntion
bpf_ktime_get_ns(), so we have to make ourselves one.

Now, why would we need to do this, well, idk. I'll try my best to figure it out.
*/
func GetNanosecSinceBoot() uint64 {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)

	if err != nil {
		log.Println("Could not get MONOTONIC Clock time ", err)
		return 0
	}
	return uint64(ts.Nsec + ts.Sec*int64(time.Second))
}
