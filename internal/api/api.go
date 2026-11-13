// Package api defines the messages exchanged by SecureSDP components.
//
// Initiating hosts talk to their domain controller over HTTPS with mutual
// TLS (paths below). Controllers and accepting hosts use the persistent
// control channel of package rpc (methods below).
package api

import (
	"encoding/json"
	"time"
)

// HTTPS endpoints served by every controller (root and bridge).
const (
	PathHealth   = "/healthz"
	PathWhoAmI   = "/v1/whoami"
	PathServices = "/v1/services"
	PathAccess   = "/v1/access"

	// Admin endpoints (root controller only, admin identities only).
	PathAdminGateways = "/v1/admin/gateways"
	PathAdminGrants   = "/v1/admin/grants"
	PathAdminRevoke   = "/v1/admin/revoke"
	PathAdminAudit    = "/v1/admin/audit"   // POST {"gateway": id}
	PathAdminHarden   = "/v1/admin/harden"  // POST {"gateway": id}
	PathAdminProfile  = "/v1/admin/profile" // GET ?gateway=id
	PathAdminReload   = "/v1/admin/reload"
)

// Control-channel methods.
const (
	// bridge -> root
	MethodAuthorize       = "authorize"
	MethodServices        = "services"
	MethodGatewayAttached = "gateway.attached"
	MethodGatewayDetached = "gateway.detached"
	// root -> bridge
	MethodGatewayCall = "gateway.call"
	// controller -> accepting host
	MethodSync         = "gateway.sync"
	MethodGrantInstall = "grant.install"
	MethodGrantRevoke  = "grant.revoke"
	MethodAudit        = "audit.run"
)

// Service modes.
const (
	// ModeForward: fwknopd DNATs the authorized client to the protected
	// service (FORCE_NAT) for the access window.
	ModeForward = "forward"
	// ModeTunnel: the accepting host terminates an mTLS tunnel from the
	// client, checks the client identity against the grant and proxies to
	// the protected service (mTLS data channel).
	ModeTunnel = "tunnel"
)

// WhoAmI describes the caller and the controller that answered.
type WhoAmI struct {
	Identity   string `json:"identity"`
	Controller string `json:"controller"`
	Role       string `json:"role"` // root or bridge
}

// AccessRequest is sent by an initiating host.
type AccessRequest struct {
	Service string `json:"service"`
}

// ServiceInfo is a service visible to a client.
type ServiceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Mode        string `json:"mode"`
	Gateway     string `json:"gateway"`
	Online      bool   `json:"online"`
}

// GatewayEndpoint tells a client where an accepting host listens.
type GatewayEndpoint struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Address string `json:"address"`
	SPAPort int    `json:"spa_port"`
}

// SPACredentials are the per-grant fwknop keys issued by the root controller.
type SPACredentials struct {
	KeyBase64     string `json:"key_base64"`
	HMACKeyBase64 string `json:"hmac_key_base64"`
	HMACDigest    string `json:"hmac_digest"`
}

// AccessGrant is the authorization returned to an initiating host.
type AccessGrant struct {
	GrantID       string          `json:"grant_id"`
	Client        string          `json:"client"`
	Service       string          `json:"service"`
	Mode          string          `json:"mode"`
	Gateway       GatewayEndpoint `json:"gateway"`
	Protocol      string          `json:"protocol"`
	Port          int             `json:"port"` // port to send SPA for and connect to on the gateway
	SPA           SPACredentials  `json:"spa"`
	AccessTimeout int             `json:"access_timeout"` // seconds the firewall stays open after SPA
	ExpiresAt     time.Time       `json:"expires_at"`     // credentials validity
	// Path lists the controllers that handled the request, closest first.
	Path []string `json:"path"`
}

// AuthorizeRequest is relayed by a bridge controller to the root controller.
// The client certificate chain is forwarded so that the root verifies the
// client identity itself.
type AuthorizeRequest struct {
	ClientChain [][]byte `json:"client_chain"`
	Service     string   `json:"service"`
	Path        []string `json:"path"`
}

// ServicesRequest is relayed by a bridge controller to list a client's services.
type ServicesRequest struct {
	ClientChain [][]byte `json:"client_chain"`
}

// GatewayAttached announces an accepting host connected to a bridge controller.
type GatewayAttached struct {
	Chain [][]byte `json:"chain"`
}

// GatewayRef names an accepting host.
type GatewayRef struct {
	Gateway string `json:"gateway"`
}

// GatewayCall asks a bridge controller to forward a call to one of its accepting hosts.
type GatewayCall struct {
	Gateway string          `json:"gateway"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// GatewayGrant is what an accepting host needs to enforce one authorization.
type GatewayGrant struct {
	ID            string    `json:"id"`
	Client        string    `json:"client"` // identity URI
	Service       string    `json:"service"`
	Mode          string    `json:"mode"`
	Protocol      string    `json:"protocol"`
	Port          int       `json:"port"`   // gateway port opened for the client
	Target        string    `json:"target"` // host:port of the protected service
	KeyBase64     string    `json:"key_base64"`
	HMACKeyBase64 string    `json:"hmac_key_base64"`
	HMACDigest    string    `json:"hmac_digest"`
	AccessTimeout int       `json:"access_timeout"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// RevokeRequest withdraws grants on an accepting host.
type RevokeRequest struct {
	IDs []string `json:"ids"`
}

// HardeningProfile is the Aspida program the controller wants applied on an
// accepting host, derived from the services that host exposes.
type HardeningProfile struct {
	Name     string   `json:"name"`
	Services []string `json:"services"`
	Aspida   string   `json:"aspida"`
	Hash     string   `json:"hash"`
}

// Sync is the full desired state of an accepting host.
type Sync struct {
	Grants    []GatewayGrant    `json:"grants"`
	Hardening *HardeningProfile `json:"hardening,omitempty"`
}

// Hardening statuses.
const (
	HardeningApplied   = "applied"
	HardeningDryRun    = "dry-run"
	HardeningUnchanged = "unchanged"
	HardeningFailed    = "failed"
)

// HardeningReport is returned by an accepting host after a sync.
type HardeningReport struct {
	Driver      string    `json:"driver"`
	Status      string    `json:"status"`
	ProfileHash string    `json:"profile_hash"`
	File        string    `json:"file,omitempty"`
	Message     string    `json:"message,omitempty"`
	Output      string    `json:"output,omitempty"`
	At          time.Time `json:"at"`
}

// SyncResult is the answer to MethodSync.
type SyncResult struct {
	Grants    int              `json:"grants"`
	Hardening *HardeningReport `json:"hardening,omitempty"`
}

// AuditReport summarizes a Lynis run on an accepting host.
type AuditReport struct {
	Gateway        string    `json:"gateway"`
	Tool           string    `json:"tool"`
	Available      bool      `json:"available"`
	Version        string    `json:"version,omitempty"`
	HardeningIndex int       `json:"hardening_index"`
	TestsPerformed int       `json:"tests_performed"`
	Warnings       int       `json:"warnings"`
	Suggestions    int       `json:"suggestions"`
	Duration       string    `json:"duration,omitempty"`
	Message        string    `json:"message,omitempty"`
	At             time.Time `json:"at"`
}

// GatewayStatus is reported by the root controller admin API.
type GatewayStatus struct {
	ID          string           `json:"id"`
	Domain      string           `json:"domain"`
	Address     string           `json:"address"`
	Online      bool             `json:"online"`
	Via         string           `json:"via"` // "direct" or the bridge controller identity
	ConnectedAt *time.Time       `json:"connected_at,omitempty"`
	Services    []string         `json:"services"`
	Grants      int              `json:"grants"`
	Hardening   *HardeningReport `json:"hardening,omitempty"`
	Audit       *AuditReport     `json:"audit,omitempty"`
}

// GrantInfo is a grant without its secrets, for the admin API.
type GrantInfo struct {
	ID        string    `json:"id"`
	Client    string    `json:"client"`
	Service   string    `json:"service"`
	Gateway   string    `json:"gateway"`
	Via       []string  `json:"via"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AdminRevoke selects grants to revoke (by ID or by client name domain/id).
type AdminRevoke struct {
	Grant  string `json:"grant,omitempty"`
	Client string `json:"client,omitempty"`
}

// RevokeResult reports how many grants were revoked.
type RevokeResult struct {
	Revoked int `json:"revoked"`
}

// ErrorBody is the JSON body of HTTPS error responses.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
