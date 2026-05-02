package setting

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
		} else if p.PresetKey == "yaoagents" {
			m["is_cloud"] = true
			m["url_editable"] = false
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
// Cloud preset helpers
// ---------------------------------------------------------------------------

var (
	cloudModelCache    []map[string]interface{}
	cloudModelCacheURL string
	cloudModelCacheMu  sync.Mutex
)

func buildCloudPreset(info *oauthTypes.AuthorizedInfo) {
	var saved map[string]interface{}
	if setting.Global != nil {
		saved, _ = setting.Global.GetMerged(info.UserID, info.TeamID, cloudNS)
	}

	apiURL := resolveCloudAPIURL(saved)
	preset := llmprovider.ProviderPreset{
		Key:        "yaoagents",
		Name:       "Yao Agents",
		Type:       "openai",
		APIURL:     apiURL,
		RequireKey: false,
		IsCloud:    true,
	}

	status, _ := saved["status"].(string)
	if status == "connected" {
		if encKey, _ := saved["api_key"].(string); encKey != "" {
			raw := fetchCloudModels(apiURL, cloudDecrypt(encKey))
			if len(raw) > 0 {
				rawJSON, _ := json.Marshal(raw)
				var models []llmprovider.ModelInfo
				if err := json.Unmarshal(rawJSON, &models); err == nil {
					for i := range models {
						models[i].Enabled = true
					}
					preset.DefaultModels = models
				}
			}
		}
	}

	llmprovider.RegisterPreset(preset)
}

func resolveCloudAPIURL(saved map[string]interface{}) string {
	if saved != nil {
		if v, ok := saved["api_url"].(string); ok && v != "" {
			return v
		}
	}
	def := cloudDefaultRegion()
	return def.APIURL
}

func fetchCloudModels(apiURL, apiKey string) []map[string]interface{} {
	cloudModelCacheMu.Lock()
	if cloudModelCache != nil && cloudModelCacheURL == apiURL {
		cached := cloudModelCache
		cloudModelCacheMu.Unlock()
		return cached
	}
	cloudModelCacheMu.Unlock()

	url := apiURL
	if strings.HasSuffix(url, "/") {
		url += "v1/models"
	} else {
		url += "/v1/models"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	models := make([]map[string]interface{}, 0, len(result.Data))
	for _, item := range result.Data {
		m := mapCloudModel(item)
		if m != nil {
			models = append(models, m)
		}
	}

	cloudModelCacheMu.Lock()
	cloudModelCache = models
	cloudModelCacheURL = apiURL
	cloudModelCacheMu.Unlock()

	return models
}

func invalidateCloudModelCache() {
	cloudModelCacheMu.Lock()
	cloudModelCache = nil
	cloudModelCacheURL = ""
	cloudModelCacheMu.Unlock()
}

func mapCloudModel(item map[string]interface{}) map[string]interface{} {
	id, _ := item["id"].(string)
	if id == "" {
		return nil
	}

	name := id
	if label, ok := item["label"].(string); ok && label != "" {
		name = strings.TrimPrefix(label, "Yao Agents / ")
		name = strings.TrimPrefix(name, "Yao Agents /")
	}

	caps := make([]string, 0)
	mode, _ := item["mode"].(string)
	switch mode {
	case "embedding":
		caps = append(caps, "embedding")
	case "audio_transcription", "audio_speech":
		caps = append(caps, "audio")
	case "image_generation":
		caps = append(caps, "image_generation")
	default:
		if getBool(item, "supports_streaming") {
			caps = append(caps, "streaming")
		}
		if getBool(item, "supports_function_calling") {
			caps = append(caps, "tool_calls")
		}
		if getBool(item, "supports_vision") {
			caps = append(caps, "vision")
		}
		if getBool(item, "supports_response_schema") {
			caps = append(caps, "json")
		}
		if getBool(item, "supports_reasoning") {
			caps = append(caps, "reasoning")
		}
		if getBool(item, "supports_audio_input") {
			caps = append(caps, "audio")
		}
	}

	m := map[string]interface{}{
		"id":           id,
		"name":         name,
		"capabilities": caps,
	}

	if v, ok := getNumber(item, "max_input_tokens"); ok && v > 0 {
		m["max_input_tokens"] = int(v)
	}
	if v, ok := getNumber(item, "max_output_tokens"); ok && v > 0 {
		m["max_output_tokens"] = int(v)
	}
	opts := map[string]interface{}{}
	if dp, ok := item["params"].(map[string]interface{}); ok {
		for k, v := range dp {
			opts[k] = v
		}
	}
	if at, ok := item["api_type"].(string); ok && at != "" {
		opts["_connector_type"] = at
	}
	if len(opts) > 0 {
		m["options"] = opts
	}

	return m
}

func getBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key].(bool)
	return ok && v
}

func getNumber(m map[string]interface{}, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
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
		APIURL     string `json:"api_url"`
		APIKey     string `json:"api_key"`
		Type       string `json:"type"`
		RequireKey *bool  `json:"require_key"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.APIURL == "" {
		respondError(c, http.StatusBadRequest, "api_url is required")
		return
	}
	if input.APIKey == "" && (input.RequireKey == nil || *input.RequireKey) {
		response.RespondWithSuccess(c, http.StatusOK, llmprovider.ProviderTestResult{
			Success: false,
			Message: "API Key is required",
		})
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

	buildCloudPreset(info)

	locale := c.Query("locale")
	var presetList []llmprovider.ProviderPreset
	if locale != "" {
		presetList = llmprovider.GetPresetsForLocale(locale)
	} else {
		presetList = llmprovider.GetPresets()
	}
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

	var staleRoles []string
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
			staleRoles = append(staleRoles, roleName)
			continue
		}
		if !p.Enabled {
			staleRoles = append(staleRoles, roleName)
			continue
		}
		if err := llmCheckOwnership(p, info); err != nil {
			staleRoles = append(staleRoles, roleName)
			continue
		}

		modelFound := false
		for _, m := range p.Models {
			if m.ID == modelID {
				modelFound = true
				break
			}
		}
		if !modelFound {
			staleRoles = append(staleRoles, roleName)
		}
	}
	for _, role := range staleRoles {
		delete(body, role)
	}
	if _, ok := body["default"]; !ok {
		respondError(c, http.StatusBadRequest, "\"default\" role: the assigned provider no longer exists, please re-select")
		return
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
		if preset == nil && presetKey == "yaoagents" {
			buildCloudPreset(info)
			preset = llmprovider.GetPreset(presetKey)
		}
		if preset == nil {
			respondError(c, http.StatusBadRequest, fmt.Sprintf("unknown preset: %s", presetKey))
			return
		}

		provider.Key = llmprovider.ScopedKey(owner, presetKey)
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
					m.Enabled = true
					provider.Models = append(provider.Models, m)
				}
			}
		} else {
			provider.Models = make([]llmprovider.ModelInfo, len(preset.DefaultModels))
			copy(provider.Models, preset.DefaultModels)
		}

		if preset.IsCloud && provider.APIKey == "" {
			var saved map[string]interface{}
			if setting.Global != nil {
				saved, _ = setting.Global.GetMerged(info.UserID, info.TeamID, cloudNS)
			}
			if encKey, _ := saved["api_key"].(string); encKey != "" {
				provider.APIKey = cloudDecrypt(encKey)
			}
		}
	} else {
		provider.IsCustom = true

		key, _ := body["key"].(string)
		if key == "" {
			respondError(c, http.StatusBadRequest, "key is required for custom provider")
			return
		}
		provider.Key = llmprovider.ScopedKey(owner, key)

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
