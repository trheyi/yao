package setting

// Scope identifies the level at which a setting is stored.
type Scope string

const (
	ScopeSystem Scope = "system"
	ScopeTeam   Scope = "team"
	ScopeUser   Scope = "user"
)

// ScopeID fully identifies a scope instance.
// For ScopeSystem, TeamID and UserID are ignored.
// For ScopeTeam, TeamID is required.
// For ScopeUser, UserID is required.
type ScopeID struct {
	Scope  Scope  `json:"scope"`
	TeamID string `json:"team_id,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

// Entry represents a single namespace's data within a scope.
type Entry struct {
	Namespace string                 `json:"namespace"`
	Scope     ScopeID                `json:"scope"`
	Data      map[string]interface{} `json:"data"`
	UpdatedAt string                 `json:"updated_at"`
}
