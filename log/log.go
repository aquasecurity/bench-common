package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"runtime"
	"strings"
	"time"
)

const dateTimeFormat = "2006-01-02 15:04:05.000"

func ZapLogger(outputs, errOutputs []string) (logger *zap.Logger, err error) {
	var level zapcore.Level
	switch strings.ToUpper(os.Getenv("BENCH_COMMON_LOG_LEVEL")) {
	case "WARN", "WARNING":
		level = zap.WarnLevel
	case "DEBUG", "TEST":
		level = zap.DebugLevel
	case "INFO":
		level = zap.InfoLevel
	case "ERROR":
		level = zap.ErrorLevel
	default:
		level = zap.InfoLevel
	}

	config := zap.Config{
		Level:    zap.NewAtomicLevelAt(level),
		Encoding: "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:     "T",
			LevelKey:    "L",
			NameKey:     "N",
			CallerKey:   "C",
			MessageKey:  "M",
			LineEnding:  zapcore.DefaultLineEnding,
			EncodeLevel: zapcore.CapitalLevelEncoder,
			EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
				enc.AppendString(t.Format(dateTimeFormat))
			},
			EncodeDuration: zapcore.StringDurationEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	if level == zap.DebugLevel {
		config.Development = true
		config.EncoderConfig.StacktraceKey = "S"
		config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	}

	if len(outputs) > 0 {
		config.OutputPaths = outputs
	}
	if len(errOutputs) > 0 {
		config.ErrorOutputPaths = errOutputs
	}

	if runtime.GOOS == "windows" {
		config.EncoderConfig.LineEnding = "\r\n"
	}

	// enable log level coloring, but only if we're not using outputs that
	// are not stdout/stderr
	if len(config.OutputPaths) == 1 && (config.OutputPaths[0] == "stderr" || config.OutputPaths[0] == "stdout") &&
		len(config.ErrorOutputPaths) == 1 && (config.ErrorOutputPaths[0] == "stderr" || config.ErrorOutputPaths[0] == "stdout") {
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	logger, err = config.Build()
	return logger, err
}
