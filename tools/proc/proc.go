package proc

import (
	_ "embed"
	"strings"

	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/kun/exception"
)

//go:embed schema.json
var SchemaJSON []byte

// Allowed process prefixes — blocks system/internal processes.
var allowedPrefixes = []string{
	"models.",
	"schemas.",
	"stores.",
	"flows.",
	"scripts.",
	"services.",
	"tasks.",
	"schedules.",
	"widgets.",
}

// Explicitly blocked prefixes for safety.
var blockedPrefixes = []string{
	"yao.sys.",
	"yao.env.",
	"utils.",
	"tools.",
}

// Handler is the tools.processcall process handler.
// Args[0]: name (string — process name, e.g. "models.user.Find")
// Args[1]: args ([]interface{} — process arguments, optional)
func Handler(p *process.Process) interface{} {
	name := p.ArgsString(0)

	if !isAllowedProcess(name) {
		exception.New("process %s is not allowed", 403, name).Throw()
	}

	var args []interface{}
	if len(p.Args) > 1 {
		if arr, ok := p.Args[1].([]interface{}); ok {
			args = arr
		}
	}

	target, err := process.Of(name, args...)
	if err != nil {
		exception.New("process %s not found: %s", 404, name, err.Error()).Throw()
	}
	if p.Authorized != nil {
		target.WithAuthorized(p.Authorized)
	}
	target.WithSID(p.Sid)
	target.WithContext(p.Context)
	if err := target.Execute(); err != nil {
		exception.New("process %s execution failed: %s", 500, name, err.Error()).Throw()
	}
	defer target.Release()
	return target.Value()
}

func isAllowedProcess(name string) bool {
	lower := strings.ToLower(name)

	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}

	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	return false
}
