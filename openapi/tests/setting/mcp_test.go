package setting_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	mcpTypes "github.com/yaoapp/gou/mcp/types"
	gouTypes "github.com/yaoapp/gou/types"
	"github.com/yaoapp/yao/mcpclient"
	"github.com/yaoapp/yao/openapi/tests/testutils"
)

func initMcpClientRegistry(t *testing.T) {
	t.Helper()
	if mcpclient.Global == nil {
		if err := mcpclient.Init(); err != nil {
			t.Fatalf("mcpclient.Init: %v", err)
		}
	}
}

func obtainTokenInfo(t *testing.T, serverURL string) *testutils.TokenInfo {
	t.Helper()
	client := testutils.RegisterTestClient(t, "MCP Test", []string{"https://localhost/callback"})
	t.Cleanup(func() { testutils.CleanupTestClient(t, client.ClientID) })
	return testutils.ObtainAccessToken(t, serverURL, client.ClientID, client.ClientSecret, "https://localhost/callback", "openid profile")
}

func seedMCPServer(t *testing.T, ownerID, name, url string) string {
	t.Helper()
	clientID := "user." + ownerID + "." + name
	client := &mcpclient.Client{
		ClientDSL: mcpTypes.ClientDSL{
			ID:        clientID,
			Name:      name,
			Transport: mcpTypes.TransportHTTP,
			URL:       url,
			Timeout:   "30s",
			MetaInfo:  gouTypes.MetaInfo{Label: name},
		},
		Enabled: true,
		Status:  "connected",
		Source:  mcpclient.ClientSourceDynamic,
		Owner:   mcpclient.ClientOwner{Type: "user", ID: ownerID},
	}
	_, err := mcpclient.Global.Create(client)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("seedMCPServer: %v", err)
	}
	return clientID
}

// startMockMCPServer starts a minimal MCP-compatible HTTP server for testing.
// Handles JSON-RPC: initialize, notifications/initialized, tools/list.
func startMockMCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var req struct {
			JSONRPC string      `json:"jsonrpc"`
			ID      interface{} `json:"id,omitempty"`
			Method  string      `json:"method"`
		}
		json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "mock-mcp", "version": "1.0.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "echo",
							"description": "Echo tool",
							"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
						},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"error":   map[string]interface{}{"code": -32601, "message": "method not found"},
			})
		}
	}))
}

func TestMCPListServers(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	token := obtainToken(t, serverURL)

	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Contains(t, body, "servers")
	servers, ok := body["servers"].([]interface{})
	assert.True(t, ok)
	t.Logf("Listed %d MCP servers", len(servers))
}

func TestMCPListUnauthenticated(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()

	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMCPCreateServer(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	mockMCP := startMockMCPServer(t)
	defer mockMCP.Close()

	payload := map[string]interface{}{
		"name":      "test-create",
		"label":     "Test Create",
		"transport": "http",
		"url":       mockMCP.URL,
		"timeout":   "10s",
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", serverURL+baseURL()+"/setting/mcp/servers", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	createdID, _ := body["id"].(string)
	assert.NotEmpty(t, createdID)
	assert.Equal(t, "test-create", body["name"])
	assert.Equal(t, "Test Create", body["label"])
	assert.Equal(t, "connected", body["status"])
	t.Logf("Created server: %s", createdID)

	// Verify in list
	listReq, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	listReq.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	listResp, _ := http.DefaultClient.Do(listReq)
	var listBody map[string]interface{}
	json.NewDecoder(listResp.Body).Decode(&listBody)
	listResp.Body.Close()

	found := false
	for _, s := range listBody["servers"].([]interface{}) {
		if s.(map[string]interface{})["id"] == createdID {
			found = true
		}
	}
	assert.True(t, found, "created server should appear in list")

	// Cleanup
	mcpclient.Global.Delete(createdID)
}

func TestMCPCreateRejectsUnreachable(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"name":      "unreachable",
		"label":     "Unreachable",
		"transport": "http",
		"url":       "https://192.0.2.1/mcp",
		"timeout":   "3s",
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", serverURL+baseURL()+"/setting/mcp/servers", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "create should reject unreachable URL")
}

func TestMCPDuplicateName(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	clientID := seedMCPServer(t, ti.UserID, "dup-test", "https://example.com/mcp")
	defer mcpclient.Global.Delete(clientID)

	payload := map[string]interface{}{
		"name":      "dup-test",
		"label":     "Duplicate",
		"transport": "http",
		"url":       "https://example.com/mcp",
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", serverURL+baseURL()+"/setting/mcp/servers", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestMCPUpdateServer(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	mockMCP := startMockMCPServer(t)
	defer mockMCP.Close()

	clientID := seedMCPServer(t, ti.UserID, "upd-test", "https://example.com/mcp")
	defer mcpclient.Global.Delete(clientID)

	payload := map[string]interface{}{
		"label": "Updated Label",
		"url":   mockMCP.URL,
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/mcp/servers/"+clientID, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Update response (%d): %s", resp.StatusCode, string(respBody))

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	json.Unmarshal(respBody, &body)
	assert.Equal(t, "Updated Label", body["label"])
	assert.Equal(t, mockMCP.URL, body["url"])
	assert.Equal(t, "connected", body["status"])
}

func TestMCPUpdateRejectsUnreachable(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	clientID := seedMCPServer(t, ti.UserID, "upd-fail", "https://example.com/mcp")
	defer mcpclient.Global.Delete(clientID)

	payload := map[string]interface{}{
		"url": "https://192.0.2.1/mcp",
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/mcp/servers/"+clientID, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "update should reject unreachable URL")
}

func TestMCPTokenMasking(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	clientID := "user." + ti.UserID + ".mask-test"
	client := &mcpclient.Client{
		ClientDSL: mcpTypes.ClientDSL{
			ID:                 clientID,
			Name:               "mask-test",
			Transport:          mcpTypes.TransportHTTP,
			URL:                "https://example.com/mcp",
			AuthorizationToken: "Bearer sk-test-token-12345678",
			Timeout:            "30s",
			MetaInfo:           gouTypes.MetaInfo{Label: "Mask Test"},
		},
		Enabled: true,
		Status:  "connected",
		Source:  mcpclient.ClientSourceDynamic,
		Owner:   mcpclient.ClientOwner{Type: "user", ID: ti.UserID},
	}
	mcpclient.Global.Create(client)
	defer mcpclient.Global.Delete(clientID)

	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	resp, _ := http.DefaultClient.Do(req)
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	for _, s := range body["servers"].([]interface{}) {
		sm := s.(map[string]interface{})
		if sm["id"] == clientID {
			maskedToken, _ := sm["authorization_token"].(string)
			assert.True(t, strings.Contains(maskedToken, "..."), "token should be masked, got: %s", maskedToken)
			assert.NotEqual(t, "Bearer sk-test-token-12345678", maskedToken)
		}
	}
}

func TestMCPDeleteServer(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)
	ti := obtainTokenInfo(t, serverURL)

	clientID := seedMCPServer(t, ti.UserID, "del-test", "https://example.com/mcp")

	req, _ := http.NewRequest("DELETE", serverURL+baseURL()+"/setting/mcp/servers/"+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	listReq, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	listReq.Header.Set("Authorization", "Bearer "+ti.AccessToken)
	listResp, _ := http.DefaultClient.Do(listReq)
	var listBody map[string]interface{}
	json.NewDecoder(listResp.Body).Decode(&listBody)
	listResp.Body.Close()

	for _, s := range listBody["servers"].([]interface{}) {
		sm := s.(map[string]interface{})
		assert.NotEqual(t, clientID, sm["id"], "deleted server should not appear in list")
	}
}

func TestMCPACL_ReadOnlyScopeCannotWrite(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initMcpClientRegistry(t)

	readToken := obtainRestrictedToken(t, serverURL, "setting:mcp:read:all")

	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/mcp/servers", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	payload := map[string]interface{}{
		"name": "acl-test", "label": "ACL Test", "transport": "http", "url": "https://example.com/mcp",
	}
	raw, _ := json.Marshal(payload)
	req2, _ := http.NewRequest("POST", serverURL+baseURL()+"/setting/mcp/servers", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer "+readToken)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)

	req3, _ := http.NewRequest("DELETE", serverURL+baseURL()+"/setting/mcp/servers/some-id", nil)
	req3.Header.Set("Authorization", "Bearer "+readToken)
	resp3, err := http.DefaultClient.Do(req3)
	assert.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
}
