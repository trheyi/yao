package setting_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yaoapp/yao/openapi/tests/testutils"
)

// ---------------------------------------------------------------------------
// Functional tests (system:root token)
// ---------------------------------------------------------------------------

func TestSmtpGet(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/smtp", nil)
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

	assert.Contains(t, body, "presets")
	assert.Contains(t, body, "config")

	presets, ok := body["presets"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 6, len(presets), "should have 6 en-us presets: gmail, yahoo, sendgrid, mailgun, ses, custom")

	config, ok := body["config"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, false, config["enabled"])
	assert.Equal(t, "unconfigured", config["status"])
	assert.Equal(t, "gmail", config["preset_key"], "default preset for en-us should be gmail")
	assert.Equal(t, "", config["password"], "password should be empty when unconfigured")
}

func TestSmtpGetZhCN(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/smtp?locale=zh-cn", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	presets, ok := body["presets"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 6, len(presets), "should have 6 zh-cn presets: tencent, feishu, aliyun, qq, netease163, custom")

	first, _ := presets[0].(map[string]interface{})
	assert.Equal(t, "tencent", first["key"])

	config, _ := body["config"].(map[string]interface{})
	assert.Equal(t, "tencent", config["preset_key"], "default preset for zh-cn should be tencent")
}

func TestSmtpGetUnauthenticated(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()

	req, err := http.NewRequest("GET", serverURL+baseURL()+"/setting/smtp", nil)
	assert.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSmtpUpdate(t *testing.T) {
	host := os.Getenv("RELIABLE_SMTP_HOST")
	port := os.Getenv("RELIABLE_SMTP_PORT")
	user := os.Getenv("RELIABLE_SMTP_USERNAME")
	pass := os.Getenv("RELIABLE_SMTP_PASSWORD")
	if host == "" || user == "" || pass == "" {
		host = os.Getenv("SMTP_HOST")
		port = os.Getenv("SMTP_PORT")
		user = os.Getenv("SMTP_USERNAME")
		pass = os.Getenv("SMTP_PASSWORD")
	}
	if host == "" || user == "" || pass == "" {
		t.Skip("SMTP credentials not set, skipping")
	}
	portNum := 465
	if port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			portNum = p
		}
	}

	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"preset_key": "custom",
		"host":       host,
		"port":       portNum,
		"encryption": "ssl",
		"username":   user,
		"password":   pass,
		"from_name":  "Test Sender",
		"from_email": user,
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Equal(t, host, body["host"])
	assert.Equal(t, user, body["username"])
	maskedPwd, _ := body["password"].(string)
	assert.True(t, strings.Contains(maskedPwd, "..."), "password should be masked: got %s", maskedPwd)

	// GET should also return masked password
	req2, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/smtp", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()

	var getData map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&getData)
	config, _ := getData["config"].(map[string]interface{})
	getMasked, _ := config["password"].(string)
	assert.True(t, strings.Contains(getMasked, "..."), "GET should return masked password")
}

func TestSmtpUpdateValidationFailure(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	payload := map[string]interface{}{
		"preset_key": "gmail",
		"host":       "smtp.gmail.com",
		"port":       465,
		"encryption": "ssl",
		"username":   "fake@gmail.com",
		"password":   "wrong-password",
		"from_name":  "Test",
		"from_email": "fake@gmail.com",
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "should reject invalid SMTP credentials")
}

func TestSmtpUpdateKeepPassword(t *testing.T) {
	host := os.Getenv("RELIABLE_SMTP_HOST")
	port := os.Getenv("RELIABLE_SMTP_PORT")
	user := os.Getenv("RELIABLE_SMTP_USERNAME")
	pass := os.Getenv("RELIABLE_SMTP_PASSWORD")
	if host == "" || user == "" || pass == "" {
		host = os.Getenv("SMTP_HOST")
		port = os.Getenv("SMTP_PORT")
		user = os.Getenv("SMTP_USERNAME")
		pass = os.Getenv("SMTP_PASSWORD")
	}
	if host == "" || user == "" || pass == "" {
		t.Skip("SMTP credentials not set, skipping")
	}
	portNum := 465
	if port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			portNum = p
		}
	}

	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	// First save with password
	payload1 := map[string]interface{}{
		"preset_key": "custom",
		"host":       host,
		"port":       portNum,
		"encryption": "ssl",
		"username":   user,
		"password":   pass,
		"from_name":  "Test",
		"from_email": user,
	}
	raw, _ := json.Marshal(payload1)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	// Update without password — should keep original and re-validate with existing password
	payload2 := map[string]interface{}{
		"preset_key": "custom",
		"host":       host,
		"port":       portNum,
		"encryption": "ssl",
		"username":   user,
		"password":   "",
		"from_name":  "Updated",
		"from_email": user,
	}
	raw, _ = json.Marshal(payload2)
	req2, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body)
	assert.Equal(t, "Updated", body["from_name"])
	keepMasked, _ := body["password"].(string)
	assert.True(t, strings.Contains(keepMasked, "..."), "password should be masked (kept original)")
}

func TestSmtpToggle(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	// Save config first
	savePayload := map[string]interface{}{
		"preset_key": "gmail",
		"host":       "smtp.gmail.com",
		"port":       465,
		"encryption": "ssl",
		"username":   "test@gmail.com",
		"password":   "test-pass",
		"from_name":  "Test",
		"from_email": "test@gmail.com",
	}
	raw, _ := json.Marshal(savePayload)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	// Enable
	enablePayload := map[string]interface{}{"enabled": true}
	raw, _ = json.Marshal(enablePayload)
	req2, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp/toggle", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body)
	assert.Equal(t, true, body["enabled"])

	// Disable
	disablePayload := map[string]interface{}{"enabled": false}
	raw, _ = json.Marshal(disablePayload)
	req3, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp/toggle", bytes.NewReader(raw))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := http.DefaultClient.Do(req3)
	assert.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	var body2 map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&body2)
	assert.Equal(t, false, body2["enabled"])
	assert.Equal(t, "unconfigured", body2["status"])
}

func TestSmtpTest(t *testing.T) {
	host := os.Getenv("RELIABLE_SMTP_HOST")
	port := os.Getenv("RELIABLE_SMTP_PORT")
	user := os.Getenv("RELIABLE_SMTP_USERNAME")
	pass := os.Getenv("RELIABLE_SMTP_PASSWORD")
	if host == "" || user == "" || pass == "" {
		host = os.Getenv("SMTP_HOST")
		port = os.Getenv("SMTP_PORT")
		user = os.Getenv("SMTP_USERNAME")
		pass = os.Getenv("SMTP_PASSWORD")
	}
	if host == "" || user == "" || pass == "" {
		t.Skip("RELIABLE_SMTP_* or SMTP_* env not set, skipping SMTP test")
	}

	toEmail := os.Getenv("SMTP_TEST_TO")
	if toEmail == "" {
		toEmail = user
	}

	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)
	token := obtainToken(t, serverURL)

	portNum := 465
	if port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			portNum = p
		}
	}

	savePayload := map[string]interface{}{
		"preset_key": "custom",
		"host":       host,
		"port":       portNum,
		"encryption": "ssl",
		"username":   user,
		"password":   pass,
		"from_name":  "Yao SMTP Test",
		"from_email": user,
	}
	raw, _ := json.Marshal(savePayload)
	req, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	testPayload := map[string]interface{}{"to_email": toEmail}
	raw, _ = json.Marshal(testPayload)
	req2, err := http.NewRequest("POST", serverURL+baseURL()+"/setting/smtp/test", bytes.NewReader(raw))
	assert.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var body map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&body)
	t.Logf("SMTP test result: %+v", body)
	assert.Equal(t, true, body["success"])
}

// ---------------------------------------------------------------------------
// ACL permission tests
// ---------------------------------------------------------------------------

func TestSmtpACL_ReadOnlyScopeCannotWrite(t *testing.T) {
	serverURL := testutils.Prepare(t)
	defer testutils.Clean()
	initSettingRegistry(t)

	readToken := obtainRestrictedToken(t, serverURL, "setting:smtp:read:all")

	// GET should work
	req, _ := http.NewRequest("GET", serverURL+baseURL()+"/setting/smtp", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "read-only scope should allow GET")

	// PUT should be denied
	payload := map[string]interface{}{
		"preset_key": "gmail",
		"host":       "smtp.gmail.com",
		"port":       465,
		"encryption": "ssl",
		"username":   "test@gmail.com",
		"password":   "test-pass",
		"from_name":  "Test",
		"from_email": "test@gmail.com",
	}
	raw, _ := json.Marshal(payload)
	req2, _ := http.NewRequest("PUT", serverURL+baseURL()+"/setting/smtp", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer "+readToken)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode, "read-only scope should deny PUT")
}
