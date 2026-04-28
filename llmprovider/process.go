package llmprovider

import (
	"encoding/json"

	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/kun/exception"
)

func init() {
	process.RegisterGroup("llmprovider", map[string]process.Handler{
		"get":        ProcessGet,
		"getmasked":  ProcessGetMasked,
		"create":     ProcessCreate,
		"update":     ProcessUpdate,
		"delete":     ProcessDelete,
		"list":       ProcessList,
		"getsetting": ProcessGetSetting,
		"getpresets": ProcessGetPresets,
		"getpreset":  ProcessGetPreset,
	})
}

func requireGlobal() {
	if Global == nil {
		exception.New("LLM Provider Registry not initialized", 500).Throw()
	}
}

// ProcessGet retrieves a provider by key.
// Args[0] string: provider key
func ProcessGet(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	key := p.ArgsString(0)

	provider, err := Global.Get(key)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return provider
}

// ProcessGetMasked retrieves a provider with API key masked.
// Args[0] string: provider key
func ProcessGetMasked(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	key := p.ArgsString(0)

	provider, err := Global.GetMasked(key)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return provider
}

// ProcessCreate adds a new provider.
// Args[0] map: Provider data
func ProcessCreate(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)

	var provider Provider
	raw, err := json.Marshal(p.Args[0])
	if err != nil {
		exception.New("invalid provider data: "+err.Error(), 400).Throw()
	}
	if err := json.Unmarshal(raw, &provider); err != nil {
		exception.New("invalid provider data: "+err.Error(), 400).Throw()
	}

	result, err := Global.Create(&provider)
	if err != nil {
		exception.New(err.Error(), 400).Throw()
	}
	return result
}

// ProcessUpdate modifies an existing provider.
// Args[0] string: provider key
// Args[1] map: Provider data
func ProcessUpdate(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(2)
	key := p.ArgsString(0)

	var provider Provider
	raw, err := json.Marshal(p.Args[1])
	if err != nil {
		exception.New("invalid provider data: "+err.Error(), 400).Throw()
	}
	if err := json.Unmarshal(raw, &provider); err != nil {
		exception.New("invalid provider data: "+err.Error(), 400).Throw()
	}

	result, err := Global.Update(key, &provider)
	if err != nil {
		exception.New(err.Error(), 400).Throw()
	}
	return result
}

// ProcessDelete removes a provider by key.
// Args[0] string: provider key
func ProcessDelete(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	key := p.ArgsString(0)

	if err := Global.Delete(key); err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return nil
}

// ProcessList returns providers matching a filter.
// Args[0] map: ProviderFilter (optional)
func ProcessList(p *process.Process) interface{} {
	requireGlobal()

	var filter *ProviderFilter
	if len(p.Args) > 0 && p.Args[0] != nil {
		raw, err := json.Marshal(p.Args[0])
		if err == nil {
			var f ProviderFilter
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

// ProcessGetSetting returns the runtime connector setting map.
// Args[0] string: provider key
func ProcessGetSetting(p *process.Process) interface{} {
	requireGlobal()
	p.ValidateArgNums(1)
	key := p.ArgsString(0)

	setting, err := Global.GetSetting(key)
	if err != nil {
		exception.New(err.Error(), 404).Throw()
	}
	return setting
}

// ProcessGetPresets returns all provider presets.
func ProcessGetPresets(p *process.Process) interface{} {
	return GetPresets()
}

// ProcessGetPreset returns a single preset by key.
// Args[0] string: preset key
func ProcessGetPreset(p *process.Process) interface{} {
	p.ValidateArgNums(1)
	key := p.ArgsString(0)

	preset := GetPreset(key)
	if preset == nil {
		exception.New("preset "+key+" not found", 404).Throw()
	}
	return preset
}
