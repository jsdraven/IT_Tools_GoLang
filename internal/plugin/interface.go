package plugin

import (
	"context"
	"net/http"
)

type Plugin interface {
	Name() string
	Metadata() PluginMetadata
	Handle(ctx *TitanContext, w http.ResponseWriter, r *http.Request) error
}

type PluginMetadata struct {
	Version            string
	SupportedExtensions []string
	Description        string
}

type TitanContext struct {
	context.Context
	RequestID string
	Logger    PluginLogger
}

type PluginLogger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}
