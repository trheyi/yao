package proc

import (
	"testing"
)

func TestIsAllowedProcess(t *testing.T) {
	allowed := []string{
		"models.user.Find",
		"schemas.user.Setting",
		"stores.cache.Set",
		"flows.login.Run",
		"scripts.helper.Format",
		"services.user.Create",
		"tasks.send.Run",
		"schedules.cleanup.Run",
		"widgets.chart.Data",
	}
	for _, name := range allowed {
		if !isAllowedProcess(name) {
			t.Errorf("expected %q to be allowed", name)
		}
	}
}

func TestIsBlockedProcess(t *testing.T) {
	blocked := []string{
		"yao.sys.Exec",
		"yao.env.Get",
		"utils.str.Join",
		"tools.websearch",
		"unknown.process",
	}
	for _, name := range blocked {
		if isAllowedProcess(name) {
			t.Errorf("expected %q to be blocked", name)
		}
	}
}
