package setting_test

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yaoapp/gou/store"
	"github.com/yaoapp/yao/config"
	"github.com/yaoapp/yao/setting"
	"github.com/yaoapp/yao/test"
)

func TestMain(m *testing.M) {
	test.Prepare(nil, config.Conf)
	defer test.Clean()
	os.Exit(m.Run())
}

func setupRegistry(t *testing.T) *setting.Registry {
	t.Helper()
	test.Prepare(t, config.Conf)

	err := setting.Init()
	require.NoError(t, err)

	t.Cleanup(func() {
		s, _ := store.Get("__yao.store")
		if s != nil {
			s.Del("setting:*")
		}
		c, _ := store.Get("__yao.cache")
		if c != nil {
			c.Del("setting:*")
		}
		test.Clean()
	})

	return setting.Global
}

var systemScope = setting.ScopeID{Scope: setting.ScopeSystem}
var teamScope = setting.ScopeID{Scope: setting.ScopeTeam, TeamID: "99"}
var userScope = setting.ScopeID{Scope: setting.ScopeUser, UserID: "42"}

func TestSetAndGet(t *testing.T) {
	r := setupRegistry(t)

	data := map[string]interface{}{
		"theme":    "dark",
		"language": "zh-CN",
		"fontSize": float64(14),
	}
	entry, err := r.Set(systemScope, "preferences", data)
	require.NoError(t, err)
	assert.Equal(t, "preferences", entry.Namespace)
	assert.Equal(t, systemScope, entry.Scope)
	assert.NotEmpty(t, entry.UpdatedAt)

	got, err := r.Get(systemScope, "preferences")
	require.NoError(t, err)
	assert.Equal(t, "dark", got["theme"])
	assert.Equal(t, "zh-CN", got["language"])
	assert.Equal(t, float64(14), got["fontSize"])
}

func TestGetWithBind(t *testing.T) {
	r := setupRegistry(t)

	data := map[string]interface{}{
		"default_chat":      "gpt-4o",
		"vision_model":      "gpt-4o",
		"embedding_enabled": true,
	}
	_, err := r.Set(systemScope, "models", data)
	require.NoError(t, err)

	type ModelsConfig struct {
		DefaultChat      string `json:"default_chat"`
		VisionModel      string `json:"vision_model"`
		EmbeddingEnabled bool   `json:"embedding_enabled"`
	}

	var cfg ModelsConfig
	raw, err := r.Get(systemScope, "models", &cfg)
	require.NoError(t, err)

	assert.Equal(t, "gpt-4o", raw["default_chat"])
	assert.Equal(t, "gpt-4o", cfg.DefaultChat)
	assert.Equal(t, "gpt-4o", cfg.VisionModel)
	assert.True(t, cfg.EmbeddingEnabled)
}

func TestGetMergedWithBind(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "prefs", map[string]interface{}{
		"theme": "dark", "lang": "zh-CN", "font_size": float64(14),
	})
	require.NoError(t, err)

	_, err = r.Set(teamScope, "prefs", map[string]interface{}{
		"lang": "en-US",
	})
	require.NoError(t, err)

	_, err = r.Set(userScope, "prefs", map[string]interface{}{
		"theme": "light",
	})
	require.NoError(t, err)

	type Prefs struct {
		Theme    string  `json:"theme"`
		Lang     string  `json:"lang"`
		FontSize float64 `json:"font_size"`
	}

	var p Prefs
	_, err = r.GetMerged("42", "99", "prefs", &p)
	require.NoError(t, err)
	assert.Equal(t, "light", p.Theme)
	assert.Equal(t, "en-US", p.Lang)
	assert.Equal(t, float64(14), p.FontSize)
}

func TestGetNotFound(t *testing.T) {
	r := setupRegistry(t)
	_, err := r.Get(systemScope, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetMerged(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "theme", map[string]interface{}{
		"primary": "blue", "dark_mode": true, "font": "inter",
	})
	require.NoError(t, err)

	_, err = r.Set(
		setting.ScopeID{Scope: setting.ScopeTeam, TeamID: "t1"},
		"theme",
		map[string]interface{}{"dark_mode": false},
	)
	require.NoError(t, err)

	_, err = r.Set(
		setting.ScopeID{Scope: setting.ScopeUser, UserID: "u1"},
		"theme",
		map[string]interface{}{"primary": "red"},
	)
	require.NoError(t, err)

	merged, err := r.GetMerged("u1", "t1", "theme")
	require.NoError(t, err)
	assert.Equal(t, "red", merged["primary"])
	assert.Equal(t, false, merged["dark_mode"])
	assert.Equal(t, "inter", merged["font"])
}

func TestGetMergedPartial(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "partial", map[string]interface{}{"a": "1", "b": "2"})
	require.NoError(t, err)

	// Only system + user, no team data
	_, err = r.Set(userScope, "partial", map[string]interface{}{"b": "override"})
	require.NoError(t, err)

	merged, err := r.GetMerged("42", "", "partial")
	require.NoError(t, err)
	assert.Equal(t, "1", merged["a"])
	assert.Equal(t, "override", merged["b"])
}

func TestGetMergedNoData(t *testing.T) {
	r := setupRegistry(t)
	_, err := r.GetMerged("42", "99", "nothing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no data found")
}

func TestSetOverwrite(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "overwrite", map[string]interface{}{"a": "1"})
	require.NoError(t, err)

	_, err = r.Set(systemScope, "overwrite", map[string]interface{}{"a": "2", "b": "3"})
	require.NoError(t, err)

	got, err := r.Get(systemScope, "overwrite")
	require.NoError(t, err)
	assert.Equal(t, "2", got["a"])
	assert.Equal(t, "3", got["b"])
}

func TestSetEmptyNamespace(t *testing.T) {
	r := setupRegistry(t)
	_, err := r.Set(systemScope, "", map[string]interface{}{"a": "1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "namespace is required")
}

func TestDelete(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "to-delete", map[string]interface{}{"x": "y"})
	require.NoError(t, err)

	err = r.Delete(systemScope, "to-delete")
	require.NoError(t, err)

	_, err = r.Get(systemScope, "to-delete")
	assert.Error(t, err)
}

func TestDeleteNotFound(t *testing.T) {
	r := setupRegistry(t)
	err := r.Delete(systemScope, "no-such-ns")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListNamespaces(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "ns-a", map[string]interface{}{"v": 1})
	require.NoError(t, err)
	_, err = r.Set(systemScope, "ns-b", map[string]interface{}{"v": 2})
	require.NoError(t, err)
	_, err = r.Set(teamScope, "ns-c", map[string]interface{}{"v": 3})
	require.NoError(t, err)

	sysNS, err := r.ListNamespaces(systemScope)
	require.NoError(t, err)
	assert.Contains(t, sysNS, "ns-a")
	assert.Contains(t, sysNS, "ns-b")
	assert.NotContains(t, sysNS, "ns-c")

	teamNS, err := r.ListNamespaces(teamScope)
	require.NoError(t, err)
	assert.Contains(t, teamNS, "ns-c")
}

func TestMultipleNamespaces(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(userScope, "alpha", map[string]interface{}{"color": "red"})
	require.NoError(t, err)
	_, err = r.Set(userScope, "beta", map[string]interface{}{"color": "blue"})
	require.NoError(t, err)

	a, err := r.Get(userScope, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "red", a["color"])

	b, err := r.Get(userScope, "beta")
	require.NoError(t, err)
	assert.Equal(t, "blue", b["color"])
}

func TestScopeIsolation(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "shared", map[string]interface{}{"level": "system"})
	require.NoError(t, err)
	_, err = r.Set(teamScope, "shared", map[string]interface{}{"level": "team"})
	require.NoError(t, err)
	_, err = r.Set(userScope, "shared", map[string]interface{}{"level": "user"})
	require.NoError(t, err)

	sys, err := r.Get(systemScope, "shared")
	require.NoError(t, err)
	assert.Equal(t, "system", sys["level"])

	team, err := r.Get(teamScope, "shared")
	require.NoError(t, err)
	assert.Equal(t, "team", team["level"])

	user, err := r.Get(userScope, "shared")
	require.NoError(t, err)
	assert.Equal(t, "user", user["level"])
}

func TestReload(t *testing.T) {
	r := setupRegistry(t)

	_, err := r.Set(systemScope, "reload-test", map[string]interface{}{"k": "v"})
	require.NoError(t, err)

	c, _ := store.Get("__yao.cache")
	if c != nil {
		c.Del("setting:*")
	}

	err = r.Reload()
	require.NoError(t, err)

	got, err := r.Get(systemScope, "reload-test")
	require.NoError(t, err)
	assert.Equal(t, "v", got["k"])
}

func TestConcurrency(t *testing.T) {
	r := setupRegistry(t)

	var wg sync.WaitGroup
	errCh := make(chan error, 30)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ns := fmt.Sprintf("conc-%d", idx)
			_, err := r.Set(systemScope, ns, map[string]interface{}{"idx": idx})
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ns := fmt.Sprintf("conc-%d", idx)
			_, err := r.Get(systemScope, ns)
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ns := fmt.Sprintf("conc-%d", idx)
			if err := r.Delete(systemScope, ns); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent operation error: %v", err)
	}
}
