// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package sysopenat

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type openatOpenatEventData struct {
	Syscall int8
	_       [3]byte
	Pid     uint32
	Uid     uint32
	Comm    [16]int8
	File    [128]int8
	_       [4]byte
	TsEnter uint64
	TsExit  uint64
	Ret     int32
	_       [4]byte
}

// loadOpenat returns the embedded CollectionSpec for openat.
func loadOpenat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OpenatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load openat: %w", err)
	}

	return spec, err
}

// loadOpenatObjects loads openat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*openatObjects
//	*openatPrograms
//	*openatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOpenatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOpenat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// openatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatSpecs struct {
	openatProgramSpecs
	openatMapSpecs
}

// openatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatProgramSpecs struct {
	TraceEnterOpen *ebpf.ProgramSpec `ebpf:"trace_enter_open"`
	TraceExitOpen  *ebpf.ProgramSpec `ebpf:"trace_exit_open"`
}

// openatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatMapSpecs struct {
	FileEventMap *ebpf.MapSpec `ebpf:"file_event_map"`
	TempMem      *ebpf.MapSpec `ebpf:"temp_mem"`
}

// openatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatObjects struct {
	openatPrograms
	openatMaps
}

func (o *openatObjects) Close() error {
	return _OpenatClose(
		&o.openatPrograms,
		&o.openatMaps,
	)
}

// openatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatMaps struct {
	FileEventMap *ebpf.Map `ebpf:"file_event_map"`
	TempMem      *ebpf.Map `ebpf:"temp_mem"`
}

func (m *openatMaps) Close() error {
	return _OpenatClose(
		m.FileEventMap,
		m.TempMem,
	)
}

// openatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatPrograms struct {
	TraceEnterOpen *ebpf.Program `ebpf:"trace_enter_open"`
	TraceExitOpen  *ebpf.Program `ebpf:"trace_exit_open"`
}

func (p *openatPrograms) Close() error {
	return _OpenatClose(
		p.TraceEnterOpen,
		p.TraceExitOpen,
	)
}

func _OpenatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed openat_bpfel.o
var _OpenatBytes []byte
