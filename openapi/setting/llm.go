package setting

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yaoapp/yao/config"
	"github.com/yaoapp/yao/llmprovider"
	"github.com/yaoapp/yao/openapi/oauth/authorized"
	oauthTypes "github.com/yaoapp/yao/openapi/oauth/types"
	"github.com/yaoapp/yao/openapi/response"
	"github.com/yaoapp/yao/setting"
)

var llmRolesNS = llmprovider.RolesNamespace

func llmEnsureEncKey() {
	if llmprovider.Global != nil && config.Conf.DB.AESKey != "" {
		llmprovider.Global.SetEncryptionKey(config.Conf.DB.AESKey)
	}
}

func llmOwner(info *oauthTypes.AuthorizedInfo) *llmprovider.ProviderOwner {
	if info.TeamID != "" {
		return &llmprovider.ProviderOwner{Type: "team", TeamID: info.TeamID}
	}
	return &llmprovider.ProviderOwner{Type: "user", UserID: info.UserID}
}

func llmScope(info *oauthTypes.AuthorizedInfo) setting.ScopeID {
	if info.TeamID != "" {
		return setting.ScopeID{Scope: setting.ScopeTeam, TeamID: info.TeamID}
	}
	return setting.ScopeID{Scope: setting.ScopeUser, UserID: info.UserID}
}

func llmCheckOwnership(p *llmprovider.Provider, info *oauthTypes.AuthorizedInfo) error {
	owner := llmOwner(info)
	if p.Owner.Type != owner.Type {
		return fmt.Errorf("provider not found")
	}
	if owner.Type == "team" && p.Owner.TeamID != owner.TeamID {
		return fmt.Errorf("provider not found")
	}
	if owner.Type == "user" && p.Owner.UserID != owner.UserID {
		return fmt.Errorf("provider not found")
	}
	return nil
}

func enrichProvider(p *llmprovider.Provider) map[string]interface{} {
	raw, _ := json.Marshal(p)
	var m map[string]interface{}
	json.Unmarshal(raw, &m)

	if p.PresetKey != "" {
		if preset := llmprovider.GetPreset(p.PresetKey); preset != nil {
			m["is_cloud"] = preset.IsCloud
			m["url_editable"] = preset.URLEditable
		}
	}

	delete(m, "connector_id")
	delete(m, "source")
	delete(m, "owner")

	return m
}

// llmModelsURL builds the models endpoint URL.
// Trailing slash means the user already specified the path prefix → append "models".
// No trailing slash → append "/v1/models" (standard OpenAI convention).
func llmModelsURL(apiURL string) string {
	if strings.HasSuffix(apiURL, "/") {
		return apiURL + "models"
	}
	return apiURL + "/v1/models"
}

// llmValidateKey tests connectivity by calling GET {apiURL}/models.
// providerType controls the auth header format (anthropic uses x-api-key).
func llmValidateKey(providerType, apiURL, apiKey string) error {
	url := llmModelsURL(apiURL)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	if apiKey != "" {
		if providerType == "anthropic" {
			req.Header.Set("x-api-key", apiKey)
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleLLMTest validates an API URL + Key without saving.
// POST /setting/llm/test
func handleLLMTest(c *gin.Context) {
	if !guardOwner(c) {
		return
	}

	var input struct {
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
		Type   string `json:"type"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.APIURL == "" {
		respondError(c, http.StatusBadRequest, "api_url is required")
		return
	}

	url := llmModelsURL(input.APIURL)
	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	if input.APIKey != "" {
		if input.Type == "anthropic" {
			req.Header.Set("x-api-key", input.APIKey)
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("Authorization", "Bearer "+input.APIKey)
		}
	}

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		response.RespondWithSuccess(c, http.StatusOK, llmprovider.ProviderTestResult{
			Success: false,
			Message: fmt.Sprintf("Connection failed: %s", err.Error()),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		response.RespondWithSuccess(c, http.StatusOK, llmprovider.ProviderTestResult{
			Success: false,
			Message: fmt.Sprintf("Server returned HTTP %d", resp.StatusCode),
		})
		return
	}

	response.RespondWithSuccess(c, http.StatusOK, llmprovider.ProviderTestResult{
		Success:   true,
		Message:   "Connection successful",
		LatencyMs: latency,
	})
}

// handleLLMGet returns the aggregated LLM configuration page data.
// GET /setting/llm
func handleLLMGet(c *gin.Context) {
	info := authorized.GetInfo(c)

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	owner := llmOwner(info)
	filter := &llmprovider.ProviderFilter{
		Owner:  owner,
		Source: llmprovider.ProviderSourceAll,
	}
	providers, err := llmprovider.Global.List(filter)
	if err != nil {
		providers = []llmprovider.Provider{}
	}

	enriched := make([]interface{}, 0, len(providers))
	for i := range providers {
		enriched = append(enriched, enrichProvider(&providers[i]))
	}

	var roles map[string]interface{}
	if setting.Global != nil {
		roles, _ = setting.Global.GetMerged(info.UserID, info.TeamID, llmRolesNS)
	}
	if roles == nil {
		roles = make(map[string]interface{})
	}

	presetList := llmprovider.GetPresets()
	presetIface := make([]interface{}, len(presetList))
	for i, p := range presetList {
		raw, _ := json.Marshal(p)
		var m map[string]interface{}
		json.Unmarshal(raw, &m)
		presetIface[i] = m
	}

	response.RespondWithSuccess(c, http.StatusOK, LLMPageData{
		Providers:       enriched,
		Roles:           roles,
		PresetProviders: presetIface,
	})
}

// handleLLMRoles saves the role assignment (default models).
// PUT /setting/llm/roles
func handleLLMRoles(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)
	scope := llmScope(info)

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if _, ok := body["default"]; !ok {
		respondError(c, http.StatusBadRequest, "\"default\" role is required")
		return
	}

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	for roleName, target := range body {
		targetMap, ok := target.(map[string]interface{})
		if !ok {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("invalid target for role \"%s\"", roleName))
			return
		}

		providerKey, _ := targetMap["provider"].(string)
		modelID, _ := targetMap["model"].(string)
		if providerKey == "" || modelID == "" {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("role \"%s\" requires provider and model", roleName))
			return
		}

		p, err := llmprovider.Global.Get(providerKey)
		if err != nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("provider \"%s\" not found", providerKey))
			return
		}
		if !p.Enabled {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("provider \"%s\" is not enabled", providerKey))
			return
		}
		if err := llmCheckOwnership(p, info); err != nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("provider \"%s\" not found", providerKey))
			return
		}

		modelFound := false
		for _, m := range p.Models {
			if m.ID == modelID {
				modelFound = true
				break
			}
		}
		if !modelFound {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("model \"%s\" not found in provider \"%s\"", modelID, providerKey))
			return
		}
	}

	if setting.Global == nil {
		respondError(c, http.StatusInternalServerError, "setting registry not initialized")
		return
	}

	if _, err := setting.Global.Set(scope, llmRolesNS, body); err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	response.RespondWithSuccess(c, http.StatusOK, body)
}

// handleLLMProviderCreate creates a new LLM provider (preset or custom).
// POST /setting/llm/providers
func handleLLMProviderCreate(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	var provider llmprovider.Provider
	owner := llmOwner(info)
	provider.Owner = *owner
	provider.Source = llmprovider.ProviderSourceDynamic
	provider.Enabled = true

	presetKey, _ := body["preset_key"].(string)

	if presetKey != "" {
		preset := llmprovider.GetPreset(presetKey)
		if preset == nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("unknown preset: %s", presetKey))
			return
		}

		provider.Key = presetKey
		provider.Name = preset.Name
		provider.Type = preset.Type
		provider.APIURL = preset.APIURL
		provider.RequireKey = preset.RequireKey
		provider.PresetKey = presetKey

		if v, ok := body["api_url"].(string); ok && v != "" {
			provider.APIURL = v
		}
		if v, ok := body["api_key"].(string); ok && v != "" {
			provider.APIKey = v
		}
		if v, ok := body["name"].(string); ok && v != "" {
			provider.Name = v
		}

		modelIDs, hasModelIDs := body["model_ids"].([]interface{})
		if hasModelIDs && len(modelIDs) > 0 {
			idSet := make(map[string]bool, len(modelIDs))
			for _, id := range modelIDs {
				if s, ok := id.(string); ok {
					idSet[s] = true
				}
			}
			for _, m := range preset.DefaultModels {
				if idSet[m.ID] {
					provider.Models = append(provider.Models, m)
				}
			}
		} else {
			provider.Models = make([]llmprovider.ModelInfo, len(preset.DefaultModels))
			copy(provider.Models, preset.DefaultModels)
		}
	} else {
		provider.IsCustom = true

		key, _ := body["key"].(string)
		if key == "" {
			respondError(c, http.StatusBadRequest, "key is required for custom provider")
			return
		}
		provider.Key = key

		name, _ := body["name"].(string)
		if name == "" {
			respondError(c, http.StatusBadRequest, "name is required")
			return
		}
		provider.Name = name

		typ, _ := body["type"].(string)
		if typ == "" {
			typ = "openai"
		}
		provider.Type = typ

		provider.APIURL, _ = body["api_url"].(string)
		provider.APIKey, _ = body["api_key"].(string)

		if modelsRaw, ok := body["models"]; ok {
			raw, _ := json.Marshal(modelsRaw)
			var models []llmprovider.ModelInfo
			if err := json.Unmarshal(raw, &models); err == nil {
				provider.Models = models
			}
		}

		if v, ok := body["require_key"].(bool); ok {
			provider.RequireKey = v
		}
	}

	if provider.Models == nil {
		provider.Models = []llmprovider.ModelInfo{}
	}

	if provider.RequireKey && provider.APIKey != "" && provider.APIURL != "" {
		if err := llmValidateKey(provider.Type, provider.APIURL, provider.APIKey); err != nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("API key validation failed: %s", err.Error()))
			return
		}
	}

	created, err := llmprovider.Global.Create(&provider)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			respondError(c, http.StatusConflict, err.Error())
		} else {
			respondError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	masked, err := llmprovider.Global.GetMasked(created.Key)
	if err != nil {
		created.APIKey = ""
		response.RespondWithSuccess(c, http.StatusCreated, enrichProvider(created))
		return
	}
	response.RespondWithSuccess(c, http.StatusCreated, enrichProvider(masked))
}

// handleLLMProviderUpdate replaces a provider's configuration.
// Full replacement: api_key empty string preserves existing value.
// PUT /setting/llm/providers/:key
func handleLLMProviderUpdate(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)
	key := c.Param("key")

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	existing, err := llmprovider.Global.Get(key, true)
	if err != nil {
		respondError(c, http.StatusNotFound, fmt.Sprintf("provider \"%s\" not found", key))
		return
	}
	if err := llmCheckOwnership(existing, info); err != nil {
		respondError(c, http.StatusNotFound, err.Error())
		return
	}

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	var provider llmprovider.Provider
	provider.Key = key
	provider.Owner = existing.Owner
	provider.Source = existing.Source
	provider.ConnectorID = existing.ConnectorID
	provider.PresetKey = existing.PresetKey
	provider.IsCustom = existing.IsCustom

	if v, ok := body["name"].(string); ok {
		provider.Name = v
	} else {
		provider.Name = existing.Name
	}
	if v, ok := body["type"].(string); ok {
		provider.Type = v
	} else {
		provider.Type = existing.Type
	}
	if v, ok := body["api_url"].(string); ok {
		provider.APIURL = v
	} else {
		provider.APIURL = existing.APIURL
	}

	if v, ok := body["api_key"].(string); ok && v != "" {
		provider.APIKey = v
	} else {
		provider.APIKey = existing.APIKey
	}

	if v, ok := body["enabled"].(bool); ok {
		provider.Enabled = v
	} else {
		provider.Enabled = existing.Enabled
	}
	if v, ok := body["require_key"].(bool); ok {
		provider.RequireKey = v
	} else {
		provider.RequireKey = existing.RequireKey
	}
	if v, ok := body["status"].(string); ok {
		provider.Status = v
	} else {
		provider.Status = existing.Status
	}

	if modelsRaw, ok := body["models"]; ok {
		raw, _ := json.Marshal(modelsRaw)
		var models []llmprovider.ModelInfo
		if err := json.Unmarshal(raw, &models); err == nil {
			provider.Models = models
		}
	} else {
		provider.Models = existing.Models
	}
	if provider.Models == nil {
		provider.Models = []llmprovider.ModelInfo{}
	}

	if _, err = llmprovider.Global.Update(key, &provider); err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	masked, err := llmprovider.Global.GetMasked(key)
	if err != nil {
		provider.APIKey = ""
		response.RespondWithSuccess(c, http.StatusOK, enrichProvider(&provider))
		return
	}
	response.RespondWithSuccess(c, http.StatusOK, enrichProvider(masked))
}

// handleLLMProviderDelete removes a provider and cleans up role references.
// DELETE /setting/llm/providers/:key
func handleLLMProviderDelete(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)
	key := c.Param("key")

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	existing, err := llmprovider.Global.Get(key)
	if err != nil {
		respondError(c, http.StatusNotFound, fmt.Sprintf("provider \"%s\" not found", key))
		return
	}
	if err := llmCheckOwnership(existing, info); err != nil {
		respondError(c, http.StatusNotFound, err.Error())
		return
	}

	var warning string
	if setting.Global != nil {
		scope := llmScope(info)
		roles, _ := setting.Global.Get(scope, llmRolesNS)
		if roles != nil {
			cleaned := false
			for roleName, target := range roles {
				if targetMap, ok := target.(map[string]interface{}); ok {
					if provKey, _ := targetMap["provider"].(string); provKey == key {
						delete(roles, roleName)
						cleaned = true
					}
				}
			}
			if cleaned {
				setting.Global.Set(scope, llmRolesNS, roles)
				warning = fmt.Sprintf("roles referencing provider \"%s\" have been cleared", key)
			}
		}
	}

	if err := llmprovider.Global.Delete(key); err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	result := map[string]interface{}{"success": true}
	if warning != "" {
		result["warning"] = warning
	}
	response.RespondWithSuccess(c, http.StatusOK, result)
}

// handleLLMProviderTest tests connectivity for a provider and writes back status.
// POST /setting/llm/providers/:key/test
func handleLLMProviderTest(c *gin.Context) {
	if !guardOwner(c) {
		return
	}
	info := authorized.GetInfo(c)
	key := c.Param("key")

	if llmprovider.Global == nil {
		respondError(c, http.StatusInternalServerError, "LLM provider registry not initialized")
		return
	}

	llmEnsureEncKey()

	p, err := llmprovider.Global.Get(key, true)
	if err != nil {
		respondError(c, http.StatusNotFound, fmt.Sprintf("provider \"%s\" not found", key))
		return
	}
	if err := llmCheckOwnership(p, info); err != nil {
		respondError(c, http.StatusNotFound, err.Error())
		return
	}

	start := time.Now()
	err = llmValidateKey(p.Type, p.APIURL, p.APIKey)
	latency := time.Since(start).Milliseconds()

	var testResult llmprovider.ProviderTestResult
	if err != nil {
		testResult = llmprovider.ProviderTestResult{
			Success: false,
			Message: err.Error(),
		}
		p.Status = "disconnected"
	} else {
		testResult = llmprovider.ProviderTestResult{
			Success:   true,
			Message:   "Connection successful",
			LatencyMs: latency,
		}
		p.Status = "connected"
		llmprovider.Global.Update(key, p)
	}

	response.RespondWithSuccess(c, http.StatusOK, testResult)
}
