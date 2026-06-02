// SPDX-License-Identifier: AGPL-3.0-or-later
package adapter

import (
	"context"
	"errors"
	"IT_Tools_GoLang_New/pkg/auth"
)

// AuthAdapter is the bridge between the Kernel's auth requirements 
// and external protocol implementations (SAML, LDAP, etc.).
type AuthAdapter interface {
	auth.AuthAuthority
}

// ProtocolType defines the type of authentication protocol being used.
type ProtocolType string

const (
	ProtocolLDAP    ProtocolType = "ldap"
	ProtocolSAML    ProtocolTemplate = "saml"
	ProtocolO365    ProtocolType = "o365"
	ProtocolMock    ProtocolType = "mock"
)

// Note: I'll use a placeholder for the template type to avoid compilation errors 
// until we define the full registry.
type ProtocolTemplate = ProtocolType 
