package runner

import (
	util "github.com/hktalent/go-utils"
	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

type BigDbLog struct {
	Out output.Writer
}

func NewBigDbLog(out output.Writer) output.Writer {
	var o output.Writer = &BigDbLog{Out: out}
	go util.DoRunning()
	return o
}

func (r *BigDbLog) Close() error {
	util.CloseLogBigDb()
	r.Out.Close()
	return nil
}

func (r *BigDbLog) Write(log *clients.Response) error {
	util.PushLog(log)
	r.Out(log)
	return nil
}
