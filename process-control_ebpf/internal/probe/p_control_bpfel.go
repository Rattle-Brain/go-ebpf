// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package probe

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadP_control returns the embedded CollectionSpec for p_control.
func loadP_control() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_P_controlBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load p_control: %w", err)
	}

	return spec, err
}

// loadP_controlObjects loads p_control and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*p_controlObjects
//	*p_controlPrograms
//	*p_controlMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadP_controlObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadP_control()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// p_controlSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type p_controlSpecs struct {
	p_controlProgramSpecs
	p_controlMapSpecs
}

// p_controlSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type p_controlProgramSpecs struct {
	TraceClone  *ebpf.ProgramSpec `ebpf:"trace_clone"`
	TraceExecve *ebpf.ProgramSpec `ebpf:"trace_execve"`
	TraceFork   *ebpf.ProgramSpec `ebpf:"trace_fork"`
}

// p_controlMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type p_controlMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// p_controlObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadP_controlObjects or ebpf.CollectionSpec.LoadAndAssign.
type p_controlObjects struct {
	p_controlPrograms
	p_controlMaps
}

func (o *p_controlObjects) Close() error {
	return _P_controlClose(
		&o.p_controlPrograms,
		&o.p_controlMaps,
	)
}

// p_controlMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadP_controlObjects or ebpf.CollectionSpec.LoadAndAssign.
type p_controlMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *p_controlMaps) Close() error {
	return _P_controlClose(
		m.Events,
	)
}

// p_controlPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadP_controlObjects or ebpf.CollectionSpec.LoadAndAssign.
type p_controlPrograms struct {
	TraceClone  *ebpf.Program `ebpf:"trace_clone"`
	TraceExecve *ebpf.Program `ebpf:"trace_execve"`
	TraceFork   *ebpf.Program `ebpf:"trace_fork"`
}

func (p *p_controlPrograms) Close() error {
	return _P_controlClose(
		p.TraceClone,
		p.TraceExecve,
		p.TraceFork,
	)
}

func _P_controlClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed p_control_bpfel.o
var _P_controlBytes []byte