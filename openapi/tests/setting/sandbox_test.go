package setting_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yaoapp/yao/openapi/tests/testutils"
	"github.com/yaoapp/yao/setting"
	"github.com/yaoapp/yao/tai"
	"github.com/yaoapp/yao/tai/registry"
)

func initTaiForTest(t *testing.T) {
	t.Helper()
	if registry.Global() == nil {
		tai.InitLocal(os.Stderr, "error", "")
	}
}

func TestSandboxGet(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	initTaiForTest(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/sandbox", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	assert.NoError(t, err)

	nodes, ok := data["nodes"].([]interface{})
	assert.True(t, ok, "should have nodes array")
	assert.NotNil(t, nodes)

	regConfig, ok := data["registry"].(map[string]interface{})
	assert.True(t, ok, "should have registry object")
	assert.NotNil(t, regConfig)

	images, ok := data["images"].(map[string]interface{})
	assert.True(t, ok, "should have images object")
	assert.NotNil(t, images)

	if len(nodes) > 0 {
		node := nodes[0].(map[string]interface{})
		assert.NotEmpty(t, node["node_id"])
		assert.NotEmpty(t, node["os"])
		t.Logf("Node: %s (%s, %s)", node["node_id"], node["os"], node["arch"])
	}
}

func TestSandboxGetUnauthenticated(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/sandbox", nil)
	assert.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSandboxRegistry(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	body := map[string]string{
		"registry_url": "https://registry.example.com",
		"username":     "testuser",
		"password":     "testpass123",
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/sandbox/registry", bytes.NewReader(data))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var regData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&regData)

	assert.Equal(t, "https://registry.example.com", regData["registry_url"])
	assert.Equal(t, "testuser", regData["username"])
	pw, _ := regData["password"].(string)
	assert.NotEqual(t, "testpass123", pw, "password should be masked")
	assert.Contains(t, pw, "...", "password should contain mask")

	// Verify GET returns masked password
	initTaiForTest(t)
	req2, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/sandbox", nil)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp2) {
		return
	}
	defer resp2.Body.Close()

	var getResult map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&getResult)
	regConfig, ok := getResult["registry"].(map[string]interface{})
	if assert.True(t, ok) {
		assert.Equal(t, "https://registry.example.com", regConfig["registry_url"])
		pw2, _ := regConfig["password"].(string)
		assert.NotEqual(t, "testpass123", pw2)
		assert.Contains(t, pw2, "...")
	}
}

func TestSandboxCheckDocker(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initTaiForTest(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("POST", serverURL+baseURL()+"/setting/sandbox/nodes/local/check-docker", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	if data["docker_version"] != nil {
		ver := data["docker_version"].(string)
		assert.NotEmpty(t, ver, "docker_version should be a non-empty string when Docker is running")
		t.Logf("Docker version: %s", ver)
	} else {
		t.Log("Docker not available on local node (this is OK)")
	}
}

func TestSandboxCheckDockerNotFound(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initTaiForTest(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("POST", serverURL+baseURL()+"/setting/sandbox/nodes/nonexistent-node-id/check-docker", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSandboxImagePull(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initTaiForTest(t)
	initSettingRegistry(t)

	reg := registry.Global()
	if reg == nil {
		t.Skip("tai registry not initialized")
	}
	meta, ok := reg.Get("local")
	if !ok || !meta.Capabilities.Docker {
		t.Skip("local node has no Docker capability")
	}

	token := obtainToken(t, serverURL)

	imageID := "YWxwaW5lOmxhdGVzdA" // base64url("alpine:latest")
	req, err := http.NewRequest("POST",
		serverURL+baseURL()+"/setting/sandbox/nodes/local/images/"+imageID+"/pull", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	assert.Equal(t, "downloading", data["status"])
	t.Logf("Pull started for alpine:latest")
}

func TestSandboxImageDelete(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initTaiForTest(t)
	initSettingRegistry(t)

	reg := registry.Global()
	if reg == nil {
		t.Skip("tai registry not initialized")
	}
	meta, ok := reg.Get("local")
	if !ok || !meta.Capabilities.Docker {
		t.Skip("local node has no Docker capability")
	}

	token := obtainToken(t, serverURL)

	imageID := "bm9uZXhpc3RlbnQ6bGF0ZXN0" // base64url("nonexistent:latest")
	req, err := http.NewRequest("DELETE",
		serverURL+baseURL()+"/setting/sandbox/nodes/local/images/"+imageID, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "deleting non-existent image should return 400")
}

func TestSandboxRegistryKeepPassword(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	body := map[string]string{
		"registry_url": "https://registry.example.com",
		"username":     "user1",
		"password":     "secret123",
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/sandbox/registry", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) {
		return
	}
	resp.Body.Close()

	body2 := map[string]string{
		"registry_url": "https://registry2.example.com",
		"username":     "user2",
		"password":     "",
	}
	data2, _ := json.Marshal(body2)
	req2, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/sandbox/registry", bytes.NewReader(data2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp2) {
		return
	}
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var regData map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&regData)

	assert.Equal(t, "https://registry2.example.com", regData["registry_url"])
	assert.Equal(t, "user2", regData["username"])
	pw, _ := regData["password"].(string)
	assert.NotEmpty(t, pw, "password should still be present from previous save")
	assert.Contains(t, pw, "...")
}

func TestSandboxRegistryRequiresAuth(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()

	body := map[string]string{"registry_url": "https://example.com"}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/sandbox/registry", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

var _ = setting.Global
