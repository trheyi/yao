package setting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yaoapp/yao/config"
	"github.com/yaoapp/yao/openapi/oauth/authorized"
	oauthTypes "github.com/yaoapp/yao/openapi/oauth/types"
	"github.com/yaoapp/yao/openapi/response"
	"github.com/yaoapp/yao/setting"
	"gopkg.in/yaml.v3"
)

//go:embed cloud_presets.yml
var cloudPresetsYML []byte

const (
	cloudNS        = "cloud"
	cloudMaskChars = 4
	cloudEncPrefix = "enc:"
)

// cloudPresets holds the parsed region list from the embedded YAML.
type cloudPresets struct {
	Regions []CloudRegion `yaml:"regions"`
}

var cloudRegions []CloudRegion

func init() {
	var p cloudPresets
	if err := yaml.Unmarshal(cloudPresetsYML, &p); err == nil {
		cloudRegions = p.Regions
	}
}

func cloudDefaultRegion() CloudRegion {
	for _, r := range cloudRegions {
		if r.Default {
			return r
		}
	}
	if len(cloudRegions) > 0 {
		return cloudRegions[0]
	}
	return CloudRegion{Key: "us", APIURL: "https://api-us.yao.run"}
}

func cloudFindRegion(key string) *CloudRegion {
	for i := range cloudRegions {
		if cloudRegions[i].Key == key {
			return &cloudRegions[i]
		}
	}
	return nil
}

func cloudScope(info *oauthTypes.AuthorizedInfo) setting.ScopeID {
	if info.TeamID != "" {
		return setting.ScopeID{Scope: setting.ScopeTeam, TeamID: info.TeamID}
	}
	return setting.ScopeID{Scope: setting.ScopeUser, UserID: info.UserID}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleCloudGet returns the cloud configuration for the current team.
// GET /setting/cloud
func handleCloudGet(c *gin.Context) {
	info := authorized.GetInfo(c)
	def := cloudDefaultRegion()

	var saved map[string]interface{}
	if setting.Global != nil {
		saved, _ = setting.Global.GetMerged(info.UserID, info.TeamID, cloudNS)
	}

	data := CloudPageData{
		Regions: cloudRegions,
		Region:  def.Key,
		APIURL:  def.APIURL,
		APIKey:  "",
		Status:  "unconfigured",
	}

	if saved != nil {
		if v, ok := saved["region"].(string); ok && v != "" {
			data.Region = v
		}
		if v, ok := saved["api_url"].(string); ok && v != "" {
			data.APIURL = v
		}
		if v, ok := saved["api_key"].(string); ok && v != "" {
			data.APIKey = cloudMaskKey(cloudDecrypt(v))
		}
		if v, ok := saved["status"].(string); ok && v != "" {
			data.Status = v
		}
	}

	response.RespondWithSuccess(c, http.StatusOK, data)
}

// handleCloudUpdate saves the cloud configuration.
// When api_key is provided, validates it by calling the cloud API before saving.
// PUT /setting/cloud
func handleCloudUpdate(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)
	scope := cloudScope(info)

	var body struct {
		Region string `json:"region"`
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Region != "" {
		if r := cloudFindRegion(body.Region); r == nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("unknown region: %s", body.Region))
			return
		}
	}

	if setting.Global == nil {
		respondError(c, http.StatusInternalServerError, "setting registry not initialized")
		return
	}

	existing, _ := setting.Global.Get(scope, cloudNS)

	m := make(map[string]interface{})
	for k, v := range existing {
		m[k] = v
	}

	if body.Region != "" {
		m["region"] = body.Region
	}
	if body.APIURL != "" {
		m["api_url"] = body.APIURL
	}

	// Resolve the effective api_url for key validation
	apiURL := body.APIURL
	if apiURL == "" {
		if v, ok := m["api_url"].(string); ok {
			apiURL = v
		}
	}
	if apiURL == "" {
		if body.Region != "" {
			if r := cloudFindRegion(body.Region); r != nil {
				apiURL = r.APIURL
			}
		}
		if apiURL == "" {
			apiURL = cloudDefaultRegion().APIURL
		}
	}

	if body.APIKey != "" {
		if err := cloudValidateKey(apiURL, body.APIKey); err != nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("API key validation failed: %s", err.Error()))
			return
		}
		m["api_key"] = cloudEncrypt(body.APIKey)
		m["status"] = "connected"
	}

	hasKey := false
	if v, ok := m["api_key"].(string); ok && v != "" {
		hasKey = true
	}
	if _, ok := m["status"].(string); !ok {
		if hasKey {
			m["status"] = "disconnected"
		} else {
			m["status"] = "unconfigured"
		}
	}

	if _, err := setting.Global.Set(scope, cloudNS, m); err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	def := cloudDefaultRegion()
	result := CloudPageData{
		Regions: cloudRegions,
		Region:  def.Key,
		APIURL:  def.APIURL,
		APIKey:  "",
		Status:  "unconfigured",
	}
	if v, ok := m["region"].(string); ok && v != "" {
		result.Region = v
	}
	if v, ok := m["api_url"].(string); ok && v != "" {
		result.APIURL = v
	}
	if v, ok := m["api_key"].(string); ok && v != "" {
		result.APIKey = cloudMaskKey(cloudDecrypt(v))
	}
	if v, ok := m["status"].(string); ok && v != "" {
		result.Status = v
	}

	response.RespondWithSuccess(c, http.StatusOK, result)
}

// cloudValidateKey verifies the API key by calling GET {apiURL}/v1/models.
func cloudValidateKey(apiURL, apiKey string) error {
	url := strings.TrimRight(apiURL, "/") + "/v1/models"
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("invalid API key (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// handleCloudTest tests the cloud connection by calling GET {api_url}/v1/models.
// Caller must provide api_url and api_key in the request body.
// POST /setting/cloud/test
func handleCloudTest(c *gin.Context) {
	if !guardOwner(c) {
		return
	}

	var input struct {
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if input.APIURL == "" || input.APIKey == "" {
		respondError(c, http.StatusBadRequest, "api_url and api_key are required")
		return
	}

	url := strings.TrimRight(input.APIURL, "/") + "/v1/models"

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+input.APIKey)

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		response.RespondWithSuccess(c, http.StatusOK, CloudTestResult{
			Success: false,
			Message: fmt.Sprintf("Connection failed: %s", err.Error()),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		response.RespondWithSuccess(c, http.StatusOK, CloudTestResult{
			Success: false,
			Message: fmt.Sprintf("Server returned HTTP %d", resp.StatusCode),
		})
		return
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	response.RespondWithSuccess(c, http.StatusOK, CloudTestResult{
		Success:   true,
		Message:   "Connection successful",
		LatencyMs: latency,
	})
}

// ---------------------------------------------------------------------------
// Crypto helpers (AES-256-GCM, same scheme as llmprovider)
// ---------------------------------------------------------------------------

func cloudEncrypt(plaintext string) string {
	secret := config.Conf.DB.AESKey
	if secret == "" {
		return plaintext
	}
	enc, err := cloudEncryptString(plaintext, secret)
	if err != nil {
		return plaintext
	}
	return cloudEncPrefix + enc
}

func cloudDecrypt(value string) string {
	if !strings.HasPrefix(value, cloudEncPrefix) {
		return value
	}
	secret := config.Conf.DB.AESKey
	if secret == "" {
		return strings.TrimPrefix(value, cloudEncPrefix)
	}
	dec, err := cloudDecryptString(strings.TrimPrefix(value, cloudEncPrefix), secret)
	if err != nil {
		return value
	}
	return dec
}

func cloudMaskKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= cloudMaskChars {
		return strings.Repeat("*", len(key))
	}
	prefix := key[:3]
	suffix := key[len(key)-cloudMaskChars:]
	return prefix + "..." + suffix
}

func cloudDeriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func cloudEncryptString(plaintext, secret string) (string, error) {
	key := cloudDeriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func cloudDecryptString(encoded, secret string) (string, error) {
	key := cloudDeriveKey(secret)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
