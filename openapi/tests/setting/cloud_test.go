package setting_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yaoapp/yao/openapi/oauth"
	"github.com/yaoapp/yao/openapi/tests/testutils"
	"github.com/yaoapp/yao/setting"
)

func initSettingRegistry(t *testing.T) {
	t.Helper()
	if setting.Global == nil {
		if err := setting.Init(); err != nil {
			t.Fatalf("setting.Init: %v", err)
		}
	}
}

func obtainToken(t *testing.T, serverURL string) string {
	t.Helper()
	client := testutils.RegisterTestClient(t, "Cloud Test", []string{"https://localhost/callback"})
	t.Cleanup(func() { testutils.CleanupTestClient(t, client.ClientID) })
	token := testutils.ObtainAccessToken(t, serverURL, client.ClientID, client.ClientSecret, "https://localhost/callback", "openid profile")
	return token.AccessToken
}

// obtainRestrictedToken creates a token with specific scope (no system:root).
// Used to test ACL permission denial.
func obtainRestrictedToken(t *testing.T, serverURL, scope string) string {
	t.Helper()
	client := testutils.RegisterTestClient(t, "Cloud Restricted", []string{"https://localhost/callback"})
	t.Cleanup(func() { testutils.CleanupTestClient(t, client.ClientID) })

	oauthService := oauth.OAuth
	if oauthService == nil {
		t.Fatal("Global OAuth service not initialized")
	}

	token := testutils.ObtainAccessToken(t, serverURL, client.ClientID, client.ClientSecret, "https://localhost/callback", "openid profile")
	subject, err := oauthService.Subject(client.ClientID, token.UserID)
	if err != nil {
		t.Fatalf("Failed to create subject: %v", err)
	}

	accessToken, err := oauthService.MakeAccessToken(client.ClientID, scope, subject, 3600)
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}
	return accessToken
}

// ----------- Functional tests (system:root token) -----------

func TestCloudGet(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/cloud", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Contains(t, body, "regions")
	assert.Contains(t, body, "region")
	assert.Contains(t, body, "api_url")
	assert.Contains(t, body, "api_key")
	assert.Contains(t, body, "status")

	regions, ok := body["regions"].([]interface{})
	assert.True(t, ok)
	assert.GreaterOrEqual(t, len(regions), 4)

	assert.Equal(t, "unconfigured", body["status"])
	assert.Equal(t, "", body["api_key"])
}

func TestCloudGetUnauthenticated(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/cloud", nil)
	assert.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestCloudUpdate(t *testing.T) {
	apiKey := os.Getenv("CLOUD_TEST_API_KEY")
	if apiKey == "" {
		t.Skip("CLOUD_TEST_API_KEY not set, skipping cloud update test (key validation required)")
	}

	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"region":  "us",
		"api_url": "https://api-us.yao.run",
		"api_key": apiKey,
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, "us", body["region"])
	assert.Equal(t, "https://api-us.yao.run", body["api_url"])
	assert.Equal(t, "connected", body["status"])

	maskedKey, _ := body["api_key"].(string)
	assert.True(t, strings.Contains(maskedKey, "..."), "masked key should use prefix...suffix format")

	// GET should also return masked key and connected status
	req2, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/cloud", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()

	var body2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body2)
	assert.Equal(t, "us", body2["region"])
	assert.Equal(t, "connected", body2["status"])
}

func TestCloudUpdateInvalidKey(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"region":  "us",
		"api_url": "https://api-us.yao.run",
		"api_key": "sk-invalid-key-that-should-fail",
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "invalid API key should be rejected")
}

func TestCloudUpdateInvalidRegion(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"region":  "mars",
		"api_url": "https://api-mars.yao.run",
		"api_key": "sk-test",
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCloudTest(t *testing.T) {
	apiKey := os.Getenv("CLOUD_TEST_API_KEY")
	if apiKey == "" {
		t.Skip("CLOUD_TEST_API_KEY not set, skipping cloud connection test")
	}

	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	// Save config first (key is validated during save)
	payload := map[string]interface{}{
		"region":  "us",
		"api_url": "https://api-us.yao.run",
		"api_key": apiKey,
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test connection with explicit api_url and api_key
	testPayload := map[string]interface{}{
		"api_url": "https://api-us.yao.run",
		"api_key": apiKey,
	}
	testRaw, _ := json.Marshal(testPayload)
	req2, err := http.NewRequest("POST", serverURL+baseURL()+"/setting/cloud/test", bytes.NewReader(testRaw))
	assert.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body)
	assert.Equal(t, true, body["success"])
	assert.NotEmpty(t, body["message"])
}

// ----------- ACL permission tests -----------

func TestCloudACL_ReadOnlyScopeCannotWrite(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)

	// Token with read-only scope (no system:root, only setting:cloud:read:all)
	readToken := obtainRestrictedToken(t, serverURL, "setting:cloud:read:all")

	// GET should work
	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/cloud", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read-only scope should allow GET")

	// PUT should be denied
	payload := map[string]interface{}{
		"region":  "cn",
		"api_url": "https://api.yaoagents.cn",
		"api_key": "sk-test",
	}
	raw, _ := json.Marshal(payload)
	req2, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer "+readToken)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode, "read-only scope should deny PUT")
}

func TestCloudACL_NoScopeCannotAccess(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)

	// Token with irrelevant scope (no setting scopes at all)
	noSettingToken := obtainRestrictedToken(t, serverURL, "kb:collections:read:all")

	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/cloud", nil)
	req.Header.Set("Authorization", "Bearer "+noSettingToken)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "token without setting scope should be denied")
}

func TestCloudUpdateRegionOnly(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"region":  "cn",
		"api_url": "https://api.yaoagents.cn",
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/cloud", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "update without api_key should succeed (no validation needed)")

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Equal(t, "cn", body["region"])
	assert.Equal(t, "https://api.yaoagents.cn", body["api_url"])
}
