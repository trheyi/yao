package mcpclient

import (
	"encoding/json"

	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/kun/exception"
)

func init() {
	process.RegisterGroup("mcpclient", map[string]process.Handler{
		"get":    ProcessGet,
		"create": ProcessCreate,
		"update": ProcessUpdate,
		"delete": ProcessDelete,
		"list":   ProcessList,
	})
}

func requireGlobal() {
	if Global == nil {
		exception.New("MCP Client Registry not initialized", 500).Throw()
	}
}

// ProcessGet retrieves a client by ID.
// Args[0] string: client ID
func ProcessGet(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	id := p.ArgsString(0)

	client, err := Global.Get(id)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return client
}

// ProcessCreate adds a new MCP client.
// Args[0] map: Client data
func ProcessCreate(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)

	var client Client
	raw, err := json.Marshal(p.Args[0])
	if err != nil {
		exception.New("invalid client data: "+err.Error(), 400).Throw()
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		exception.New("invalid client data: "+err.Error(), 400).Throw()
	}

	result, err := Global.Create(&client)
	if err != nil {
		exception.New(err.Error(), 400).Throw()
	}
	return result
}

// ProcessUpdate modifies an existing MCP client.
// Args[0] string: client ID
// Args[1] map: Client data
func ProcessUpdate(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(2)
	id := p.ArgsString(0)

	var client Client
	raw, err := json.Marshal(p.Args[1])
	if err != nil {
		exception.New("invalid client data: "+err.Error(), 400).Throw()
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		exception.New("invalid client data: "+err.Error(), 400).Throw()
	}

	result, err := Global.Update(id, &client)
	if err != nil {
		exception.New(err.Error(), 400).Throw()
	}
	return result
}

// ProcessDelete removes a client by ID.
// Args[0] string: client ID
func ProcessDelete(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	id := p.ArgsString(0)

	if err := Global.Delete(id); err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return nil
}

// ProcessList returns clients matching a filter.
// Args[0] map: ClientFilter (optional)
func ProcessList(p *process.Process) interface{} {
	requireGlobal()

	var filter *ClientFilter
	if len(p.Args) > 0 && p.Args[0] != nil {
		raw, err := json.Marshal(p.Args[0])
		if err == nil {
			var f ClientFilter
			if json.Unmarshal(raw, &f) == nil {
				filter = &f
			}
		}
	}

	result, err := Global.List(filter)
	if err != nil {
		exception.New(err.Error(), 500).Throw()
	}
	return result
}
