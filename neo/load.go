package neo

import (
	"fmt"
	"path/filepath"

	"github.com/yaoapp/gou/application"
	"github.com/yaoapp/gou/connector"
	"github.com/yaoapp/yao/config"
	"github.com/yaoapp/yao/neo/assistant"
	"github.com/yaoapp/yao/neo/store"
)

// Neo the neo AI assistant
var Neo *DSL

// Load load AIGC
func Load(cfg config.Config) error {

	setting := DSL{
		ID:     "neo",
		Allows: []string{},
		StoreSetting: store.Setting{
			Prefix:    "yao_neo_",
			Connector: "default",
		},
	}

	bytes, err := application.App.Read(filepath.Join("neo", "neo.yml"))
	if err != nil {
		return err
	}

	err = application.Parse("neo.yml", bytes, &setting)
	if err != nil {
		return err
	}

	if setting.StoreSetting.MaxSize == 0 {
		setting.StoreSetting.MaxSize = 20 // default is 20
	}

	// Default Assistant, Neo is the developer name, Mohe is the brand name of the assistant
	if setting.Use == nil {
		setting.Use = &Use{Default: "mohe"} // Neo is the developer name, Mohe is the brand name of the assistant
	}

	// Title Assistant
	if setting.Use.Title == "" {
		setting.Use.Title = setting.Use.Default
	}

	// Prompt Assistant
	if setting.Use.Prompt == "" {
		setting.Use.Prompt = setting.Use.Default
	}

	Neo = &setting

	// Store Setting
	err = initStore()
	if err != nil {
		return err
	}

	// Initialize Assistant
	err = initAssistant()
	if err != nil {
		return err
	}

	return nil
}

// initStore initialize the store
func initStore() error {

	var err error
	if Neo.StoreSetting.Connector == "default" || Neo.StoreSetting.Connector == "" {
		Neo.Store, err = store.NewXun(Neo.StoreSetting)
		return err
	}

	// other connector
	conn, err := connector.Select(Neo.StoreSetting.Connector)
	if err != nil {
		return err
	}

	if conn.Is(connector.DATABASE) {
		Neo.Store, err = store.NewXun(Neo.StoreSetting)
		return err

	} else if conn.Is(connector.REDIS) {
		Neo.Store = store.NewRedis()
		return nil

	} else if conn.Is(connector.MONGO) {
		Neo.Store = store.NewMongo()
		return nil
	}

	return fmt.Errorf("%s store connector %s not support", Neo.ID, Neo.StoreSetting.Connector)
}

// initAssistant initialize the assistant
func initAssistant() error {

	// Set Storage
	assistant.SetStorage(Neo.Store)

	// Assistant Vision
	if Neo.Vision != nil {
		assistant.SetVision(Neo.Vision)
	}

	if Neo.Connectors != nil {
		assistant.SetConnectorSettings(Neo.Connectors)
	}

	// Load Built-in Assistants
	err := assistant.LoadBuiltIn()
	if err != nil {
		return err
	}

	// Default Assistant
	defaultAssistant, err := defaultAssistant()
	if err != nil {
		return err
	}

	Neo.Assistant = defaultAssistant
	return nil
}

// defaultAssistant get the default assistant
func defaultAssistant() (*assistant.Assistant, error) {
	if Neo.Use == nil || Neo.Use.Default == "" {
		return nil, fmt.Errorf("default assistant not found")
	}
	return assistant.Get(Neo.Use.Default)
}
