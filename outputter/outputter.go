package outputter

import (
	"github.com/aquasecurity/bench-common/check"
)

type Outputter interface {
	Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error
}

func OutputResults(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	// if we successfully ran some tests and it's json format, ignore the warnings
	if summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0 {
		o := &JSON{}
		err := o.Output(controls, summary, maybeConfig...)
		if err != nil {
			return err
		}
	} else {
		o := &Console{}
		err := o.Output(controls, summary, maybeConfig...)
		if err != nil {
			return err
		}
	}
	return nil
}
