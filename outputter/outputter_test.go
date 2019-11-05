package outputter

import (
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

func TestBuildOutputterJSON(t *testing.T) {
	testCases := []struct {
		summary check.Summary
		config  *Config
		match   bool
	}{
		{
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{
				JSONFormat: true,
			},
			match: true,
		},
		{
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{},
			match:  false,
		},
		{
			summary: check.Summary{},
			config:  &Config{},
			match:   false,
		},
		{
			summary: check.Summary{},
			config: &Config{
				JSONFormat: true,
			},
			match: false,
		},
	}

	for _, tc := range testCases {
		o := BuildOutputter(tc.summary, tc.config)
		if _, match := o.(*JSON); tc.match != match {
			t.Errorf("TestBuildOutputterJSON - Wrong Type returned")
		}
	}
}

func TestBuildOutputterConsole(t *testing.T) {
	testCases := []struct {
		summary check.Summary
		config  *Config
		match   bool
	}{
		{
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{
				JSONFormat: true,
			},
			match: false,
		},
		{
			summary: check.Summary{
				Pass: 1,
			},
			config: &Config{},
			match:  true,
		},
		{
			summary: check.Summary{},
			config:  &Config{},
			match:   true,
		},
		{
			summary: check.Summary{},
			config: &Config{
				JSONFormat: true,
			},
			match: true,
		},
	}

	for _, tc := range testCases {
		o := BuildOutputter(tc.summary, tc.config)
		if _, match := o.(*Console); tc.match != match {
			t.Errorf("TestBuildOutputterConsole - Wrong Type returned")
		}
	}
}

func TestBuildOutputterFunc(t *testing.T) {

	testOutputFunc := func(controls *check.Controls, summary check.Summary) error {
		return nil
	}

	testCases := []struct {
		opf  OutputFunc
		fail bool
	}{
		{
			opf:  testOutputFunc,
			fail: false,
		},
		{
			fail: true,
		},
	}

	for _, tc := range testCases {
		o, err := BuildOutputterFunc(tc.opf)
		if tc.fail {
			if err == nil {
				t.Errorf("Expected Error returned")
			}
		}

		if !tc.fail {
			if o == nil {
				t.Errorf("Expected Outputter to be returned")
			}
		}

	}
}
