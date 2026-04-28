package setting

import (
	"encoding/json"

	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/kun/exception"
)

func init() {
	process.RegisterGroup("setting", map[string]process.Handler{
		"get":            ProcessGet,
		"getmerged":      ProcessGetMerged,
		"set":            ProcessSet,
		"delete":         ProcessDelete,
		"listnamespaces": ProcessListNamespaces,
	})
}

func requireGlobal() {
	if Global == nil {
		exception.New("Setting Registry not initialized", 500).Throw()
	}
}

func parseScopeID(arg interface{}) ScopeID {
	raw, err := json.Marshal(arg)
	if err != nil {
		exception.New("invalid scope: "+err.Error(), 400).Throw()
	}
	var scope ScopeID
	if err := json.Unmarshal(raw, &scope); err != nil {
		exception.New("invalid scope: "+err.Error(), 400).Throw()
	}
	return scope
}

// ProcessGet reads a namespace entry for a given scope.
// Args[0] map: ScopeID {scope, team_id?, user_id?}
// Args[1] string: namespace
func ProcessGet(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(2)

	scope := parseScopeID(p.Args[0])
	ns := p.ArgsString(1)

	data, err := Global.Get(scope, ns)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return data
}

// ProcessGetMerged reads a namespace with three-level cascade merge.
// Args[0] string: userID
// Args[1] string: teamID
// Args[2] string: namespace
func ProcessGetMerged(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(3)

	userID := p.ArgsString(0)
	teamID := p.ArgsString(1)
	ns := p.ArgsString(2)

	data, err := Global.GetMerged(userID, teamID, ns)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return data
}

// ProcessSet writes a namespace entry for a given scope.
// Args[0] map: ScopeID
// Args[1] string: namespace
// Args[2] map: data
func ProcessSet(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(3)

	scope := parseScopeID(p.Args[0])
	ns := p.ArgsString(1)

	raw, err := json.Marshal(p.Args[2])
	if err != nil {
		exception.New("invalid data: "+err.Error(), 400).Throw()
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		exception.New("invalid data: "+err.Error(), 400).Throw()
	}

	entry, err := Global.Set(scope, ns, data)
	if err != nil {
		exception.New(err.Error(), 400).Throw()
	}
	return entry
}

// ProcessDelete removes a namespace entry from a given scope.
// Args[0] map: ScopeID
// Args[1] string: namespace
func ProcessDelete(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(2)

	scope := parseScopeID(p.Args[0])
	ns := p.ArgsString(1)

	if err := Global.Delete(scope, ns); err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return nil
}

// ProcessListNamespaces returns all namespace names under a scope.
// Args[0] map: ScopeID
func ProcessListNamespaces(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)

	scope := parseScopeID(p.Args[0])

	ns, err := Global.ListNamespaces(scope)
	if err != nil {
		exception.New(err.Error(), 500).Throw()
	}
	return ns
}
