package controller

import (
	"sort"
	"sync"
	"time"

	"github.com/antoniopaya22/Secure-SDP/internal/api"
)

type grantRecord struct {
	grant   api.GatewayGrant
	gateway string
	issued  time.Time
	via     []string
}

// grantStore keeps the active grants issued by the root controller.
type grantStore struct {
	mu sync.Mutex
	m  map[string]*grantRecord
}

func newGrantStore() *grantStore { return &grantStore{m: map[string]*grantRecord{}} }

// add stores g and removes older grants of the same client for the same
// service, returning their IDs so they can be revoked on the gateway.
func (s *grantStore) add(g *grantRecord) (superseded []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, old := range s.m {
		if old.grant.Client == g.grant.Client && old.grant.Service == g.grant.Service && old.gateway == g.gateway {
			delete(s.m, id)
			superseded = append(superseded, id)
		}
	}
	s.m[g.grant.ID] = g
	return superseded
}

func (s *grantStore) forGateway(gateway string, now time.Time) []api.GatewayGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []api.GatewayGrant{}
	for _, g := range s.m {
		if g.gateway == gateway && now.Before(g.grant.ExpiresAt) {
			out = append(out, g.grant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// expire removes expired grants, grouped by gateway.
func (s *grantStore) expire(now time.Time) map[string][]string {
	return s.revokeIf(func(g *grantRecord) bool { return !now.Before(g.grant.ExpiresAt) })
}

// revokeIf removes grants matching pred, grouped by gateway.
func (s *grantStore) revokeIf(pred func(*grantRecord) bool) map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	for id, g := range s.m {
		if pred(g) {
			delete(s.m, id)
			out[g.gateway] = append(out[g.gateway], id)
		}
	}
	return out
}

func (s *grantStore) list(now time.Time) []api.GrantInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []api.GrantInfo{}
	for _, g := range s.m {
		if !now.Before(g.grant.ExpiresAt) {
			continue
		}
		out = append(out, api.GrantInfo{
			ID: g.grant.ID, Client: g.grant.Client, Service: g.grant.Service, Gateway: g.gateway,
			Via: g.via, IssuedAt: g.issued, ExpiresAt: g.grant.ExpiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out
}
