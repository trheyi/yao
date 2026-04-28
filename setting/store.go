package setting

import (
	"encoding/json"
	"fmt"

	"github.com/yaoapp/gou/store"
)

const keyPrefix = "setting:"

func scopePrefix(scope ScopeID) string {
	switch scope.Scope {
	case ScopeTeam:
		return "t" + scope.TeamID + ":"
	case ScopeUser:
		return "u" + scope.UserID + ":"
	default:
		return "s:"
	}
}

func storeKey(scope ScopeID, ns string) string {
	return keyPrefix + scopePrefix(scope) + ns
}

func indexKey(scope ScopeID) string {
	return keyPrefix + "idx:" + scopePrefix(scope)
}

// storeGet reads a namespace entry from cache first, then persistent store.
func storeGet(s, c store.Store, scope ScopeID, ns string) (map[string]interface{}, error) {
	sk := storeKey(scope, ns)

	if c != nil {
		if val, ok := c.Get(sk); ok {
			if m, ok := val.(map[string]interface{}); ok {
				return m, nil
			}
		}
	}

	val, ok := s.Get(sk)
	if !ok {
		return nil, fmt.Errorf("setting %s/%s not found", scopePrefix(scope), ns)
	}

	m, err := toMap(val)
	if err != nil {
		return nil, fmt.Errorf("setting %s/%s: %w", scopePrefix(scope), ns, err)
	}

	if c != nil {
		c.Set(sk, m, 0)
	}
	return m, nil
}

// storeSet writes a namespace entry to both persistent store and cache.
func storeSet(s, c store.Store, scope ScopeID, ns string, data map[string]interface{}) error {
	sk := storeKey(scope, ns)
	if err := s.Set(sk, data, 0); err != nil {
		return err
	}
	if c != nil {
		c.Set(sk, data, 0)
	}
	return nil
}

// storeDel removes a namespace entry from both persistent store and cache.
func storeDel(s, c store.Store, scope ScopeID, ns string) error {
	sk := storeKey(scope, ns)
	if err := s.Del(sk); err != nil {
		return err
	}
	if c != nil {
		c.Del(sk)
	}
	return nil
}

// indexGet returns all namespace names for a given scope.
func indexGet(s, c store.Store, scope ScopeID) ([]string, error) {
	ik := indexKey(scope)
	var raw interface{}
	var ok bool

	if c != nil {
		raw, ok = c.Get(ik)
	}
	if !ok {
		raw, ok = s.Get(ik)
		if !ok {
			return nil, nil
		}
		if c != nil {
			c.Set(ik, raw, 0)
		}
	}

	switch v := raw.(type) {
	case []interface{}:
		keys := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				keys = append(keys, str)
			}
		}
		return keys, nil
	case []string:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected index type %T", raw)
	}
}

// indexSet writes the full namespace index.
func indexSet(s, c store.Store, scope ScopeID, keys []string) error {
	ik := indexKey(scope)
	iface := make([]interface{}, len(keys))
	for i, k := range keys {
		iface[i] = k
	}
	if err := s.Set(ik, iface, 0); err != nil {
		return err
	}
	if c != nil {
		c.Set(ik, iface, 0)
	}
	return nil
}

// indexAdd appends a namespace to the index if not already present.
func indexAdd(s, c store.Store, scope ScopeID, ns string) error {
	keys, err := indexGet(s, c, scope)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k == ns {
			return nil
		}
	}
	return indexSet(s, c, scope, append(keys, ns))
}

// indexRemove removes a namespace from the index.
func indexRemove(s, c store.Store, scope ScopeID, ns string) error {
	keys, err := indexGet(s, c, scope)
	if err != nil {
		return err
	}
	filtered := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != ns {
			filtered = append(filtered, k)
		}
	}
	return indexSet(s, c, scope, filtered)
}

// toMap normalizes a store value to map[string]interface{}.
// The xun store may return values that need re-serialization.
func toMap(val interface{}) (map[string]interface{}, error) {
	if m, ok := val.(map[string]interface{}); ok {
		return m, nil
	}
	raw, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
