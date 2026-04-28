package mcpclient_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yaoapp/gou/process"
)

func TestProcessCreate(t *testing.T) {
	setupRegistry(t)

	p := process.New("mcpclient.create", map[string]interface{}{
		"id":        "proc-test",
		"name":      "Proc Test",
		"type":      "standard",
		"transport": "stdio",
		"command":   "echo",
		"arguments": []interface{}{"hello"},
		"enabled":   true,
		"owner":     map[string]interface{}{"type": "system"},
	})
	result, err := p.Exec()
	require.NoError(t, err)
	require.NotNil(t, result)

	m := toMapResult(t, result)
	assert.Equal(t, "proc-test", m["id"])
	assert.NotEmpty(t, m["runtime_id"])
	assert.Equal(t, "dynamic", m["source"])
}

func TestProcessGet(t *testing.T) {
	setupRegistry(t)
	createClientViaProcess(t, "proc-get")

	p := process.New("mcpclient.get", "proc-get")
	result, err := p.Exec()
	require.NoError(t, err)

	m := toMapResult(t, result)
	assert.Equal(t, "proc-get", m["id"])
}

func TestProcessUpdate(t *testing.T) {
	setupRegistry(t)
	createClientViaProcess(t, "proc-upd")

	p := process.New("mcpclient.update", "proc-upd", map[string]interface{}{
		"name":      "Updated MCP",
		"type":      "standard",
		"transport": "stdio",
		"command":   "cat",
		"enabled":   true,
	})
	result, err := p.Exec()
	require.NoError(t, err)

	m := toMapResult(t, result)
	assert.Equal(t, "Updated MCP", m["name"])
}

func TestProcessDelete(t *testing.T) {
	setupRegistry(t)
	createClientViaProcess(t, "proc-del")

	p := process.New("mcpclient.delete", "proc-del")
	_, err := p.Exec()
	require.NoError(t, err)

	pGet := process.New("mcpclient.get", "proc-del")
	_, err = pGet.Exec()
	assert.Error(t, err)
}

func TestProcessList(t *testing.T) {
	setupRegistry(t)
	createClientViaProcess(t, "proc-list-1")
	createClientViaProcess(t, "proc-list-2")

	p := process.New("mcpclient.list", map[string]interface{}{
		"source": "dynamic",
	})
	result, err := p.Exec()
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Logf("list result type: %T", result)
}

// --- helpers ---

func createClientViaProcess(t *testing.T, id string) {
	t.Helper()
	p := process.New("mcpclient.create", map[string]interface{}{
		"id":        id,
		"name":      "Test " + id,
		"type":      "standard",
		"transport": "stdio",
		"command":   "echo",
		"arguments": []interface{}{"hello"},
		"enabled":   true,
		"owner":     map[string]interface{}{"type": "system"},
	})
	_, err := p.Exec()
	require.NoError(t, err)
}

func toMapResult(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}
