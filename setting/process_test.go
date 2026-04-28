package setting_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yaoapp/gou/process"
)

var sysScope = map[string]interface{}{"scope": "system"}
var teamScopeP = map[string]interface{}{"scope": "team", "team_id": "99"}
var userScopeP = map[string]interface{}{"scope": "user", "user_id": "42"}

func TestProcessSet(t *testing.T) {
	setupRegistry(t)

	p := process.New("setting.set", sysScope, "prefs", map[string]interface{}{
		"theme": "dark", "lang": "zh-CN",
	})
	result, err := p.Exec()
	require.NoError(t, err)
	require.NotNil(t, result)

	m := toMapR(t, result)
	assert.Equal(t, "prefs", m["namespace"])
	assert.NotEmpty(t, m["updated_at"])
}

func TestProcessGet(t *testing.T) {
	setupRegistry(t)

	process.New("setting.set", sysScope, "gettest", map[string]interface{}{
		"color": "blue",
	}).Exec()

	p := process.New("setting.get", sysScope, "gettest")
	result, err := p.Exec()
	require.NoError(t, err)

	m := toMapR(t, result)
	assert.Equal(t, "blue", m["color"])
}

func TestProcessGetMerged(t *testing.T) {
	setupRegistry(t)

	process.New("setting.set", sysScope, "merged", map[string]interface{}{
		"a": "sys", "b": "sys",
	}).Exec()
	process.New("setting.set", teamScopeP, "merged", map[string]interface{}{
		"b": "team",
	}).Exec()
	process.New("setting.set", userScopeP, "merged", map[string]interface{}{
		"a": "user",
	}).Exec()

	p := process.New("setting.getmerged", "42", "99", "merged")
	result, err := p.Exec()
	require.NoError(t, err)

	m := toMapR(t, result)
	assert.Equal(t, "user", m["a"])
	assert.Equal(t, "team", m["b"])
}

func TestProcessDelete(t *testing.T) {
	setupRegistry(t)

	process.New("setting.set", sysScope, "deltest", map[string]interface{}{
		"x": "y",
	}).Exec()

	p := process.New("setting.delete", sysScope, "deltest")
	_, err := p.Exec()
	require.NoError(t, err)

	pGet := process.New("setting.get", sysScope, "deltest")
	_, err = pGet.Exec()
	assert.Error(t, err)
}

func TestProcessListNamespaces(t *testing.T) {
	setupRegistry(t)

	process.New("setting.set", sysScope, "ns-a", map[string]interface{}{"v": 1}).Exec()
	process.New("setting.set", sysScope, "ns-b", map[string]interface{}{"v": 2}).Exec()

	p := process.New("setting.listnamespaces", sysScope)
	result, err := p.Exec()
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Logf("namespaces: %v", result)
}

// --- helpers ---

func toMapR(t *testing.T, v interface{}) map[string]interface{} {
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
