package outputter

import (
	"fmt"
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
				Format: JSONFormat,
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
				Format: JSONFormat,
			},
			match: false,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			o := BuildOutputter(tc.summary, tc.config)
			if _, match := o.(*JSON); tc.match != match {
				t.Errorf("TestBuildOutputterJSON/%d failed - Expected '*outputter.JSON' but got '%T'", i, o)
			}
		})
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
				Format: JSONFormat,
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
				Format: JSONFormat,
			},
			match: true,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			o := BuildOutputter(tc.summary, tc.config)
			if _, match := o.(*Console); tc.match != match {
				t.Errorf("TestBuildOutputterConsole/%d failed - Expected '*outputter.Console' but got '%T'", i, o)
			}
		})
	}
}

func TestBuildOutputterFunc(t *testing.T) {

	testOutputFunc := func(controls *check.Controls, summary check.Summary) error {
		return nil
	}

	testCases := []struct {
		opf  outputFunc
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
