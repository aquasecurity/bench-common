package outputter

import (
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

func TestBuildOutputterJSON(t *testing.T) {
	testCases := []struct {
		controls *check.Controls
		summary  check.Summary
		config   *Config
		match    bool
	}{
		{
			controls: &check.Controls{},
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{
				JSONFormat: true,
			},
			match: true,
		},
		{
			controls: &check.Controls{},
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{},
			match:  false,
		},
		{
			controls: &check.Controls{},
			summary:  check.Summary{},
			config:   &Config{},
			match:    false,
		},
		{
			controls: &check.Controls{},
			summary:  check.Summary{},
			config: &Config{
				JSONFormat: true,
			},
			match: false,
		},
	}

	for _, tc := range testCases {
		o := BuildOutputter(tc.controls, tc.summary, tc.config)
		if _, match := o.(*JSON); tc.match != match {
			t.Errorf("TestBuildOutputterJSON - Wrong Type returned")
		}
	}
}

func TestBuildOutputterConsole(t *testing.T) {
	testCases := []struct {
		controls *check.Controls
		summary  check.Summary
		config   *Config
		match    bool
	}{
		{
			controls: &check.Controls{},
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{
				JSONFormat: true,
			},
			match: false,
		},
		{
			controls: &check.Controls{},
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{},
			match:  true,
		},
		{
			controls: &check.Controls{},
			summary:  check.Summary{},
			config:   &Config{},
			match:    true,
		},
		{
			controls: &check.Controls{},
			summary:  check.Summary{},
			config: &Config{
				JSONFormat: true,
			},
			match: true,
		},
	}

	for _, tc := range testCases {
		o := BuildOutputter(tc.controls, tc.summary, tc.config)
		if _, match := o.(*Console); tc.match != match {
			t.Errorf("TestBuildOutputterConsole - Wrong Type returned")
		}
	}
}
