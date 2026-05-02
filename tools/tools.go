package tools

import (
	_ "embed"
	"encoding/json"

	"github.com/yaoapp/gou/mcp"
	mcpTypes "github.com/yaoapp/gou/mcp/types"
	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/kun/log"
	"github.com/yaoapp/yao/tools/docs"
	"github.com/yaoapp/yao/tools/proc"
	"github.com/yaoapp/yao/tools/webfetch"
	"github.com/yaoapp/yao/tools/websearch"
)

//go:embed mcps/web.json
var mcpWebDSL []byte

//go:embed mcps/process.json
var mcpProcessDSL []byte

//go:embed mcps/doc.json
var mcpDocDSL []byte

func init() {
	process.RegisterGroup("tools", map[string]process.Handler{
		"websearch":   websearch.Handler,
		"webfetch":    webfetch.Handler,
		"processcall": proc.Handler,
		"doclist":     docs.ListHandler,
		"docinspect":  docs.InspectHandler,
		"docvalidate": docs.ValidateHandler,
	})

	registerMCPServer(mcpWebDSL, "yao-web",
		websearch.SchemaJSON, webfetch.SchemaJSON)
	registerMCPServer(mcpProcessDSL, "yao-process",
		proc.SchemaJSON)
	registerMCPServer(mcpDocDSL, "yao-doc",
		docs.ListSchemaJSON, docs.InspectSchemaJSON, docs.ValidateSchemaJSON)
}

func registerMCPServer(dsl []byte, id string, schemas ...[]byte) {
	mapping := &mcpTypes.MappingData{
		Tools:     map[string]*mcpTypes.ToolSchema{},
		Resources: map[string]*mcpTypes.ResourceSchema{},
		Prompts:   map[string]*mcpTypes.PromptSchema{},
	}
	for _, raw := range schemas {
		var s mcpTypes.ToolSchema
		if err := json.Unmarshal(raw, &s); err != nil {
			log.Error("[tools] failed to parse schema: %s", err.Error())
			continue
		}
		mapping.Tools[s.Name] = &s
	}
	if _, err := mcp.LoadClientSourceWithType(string(dsl), id, "", mapping); err != nil {
		log.Error("[tools] failed to register MCP server %s: %s", id, err.Error())
	}
}
