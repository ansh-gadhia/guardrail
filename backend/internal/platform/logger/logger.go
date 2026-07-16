// Package logger provides a structured JSON logger (zap) configured from
// application config. Logs go to stdout (Twelve-Factor). Correlation fields
// (request_id, trace_id, session_id) are attached by middleware, not here.
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a production-grade logger. format is "json" or "console"; level is
// one of debug|info|warn|error.
func New(level, format string) (*zap.Logger, error) {
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("parse log level %q: %w", level, err)
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.MessageKey = "msg"
	encCfg.LevelKey = "level"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.LowercaseLevelEncoder

	encoding := "json"
	if format == "console" {
		encoding = "console"
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(lvl),
		Encoding:         encoding,
		EncoderConfig:    encCfg,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		// Sampling keeps log volume bounded under load without dropping the
		// first occurrences of each level.
		Sampling: &zap.SamplingConfig{Initial: 100, Thereafter: 100},
	}

	log, err := cfg.Build(zap.AddCaller())
	if err != nil {
		return nil, fmt.Errorf("build logger: %w", err)
	}
	return log, nil
}
