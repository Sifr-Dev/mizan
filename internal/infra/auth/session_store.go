package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session is the server-side state associated with one authentication family.
// The session ID (sid) remains stable across refresh rotations. AccessJTI and
// RefreshJTI identify the only currently valid token of each purpose.
type Session struct {
	ID                  string    `json:"id"`
	UserID              uuid.UUID `json:"user_id"`
	Role                string    `json:"role"`
	AccessJTI           string    `json:"access_jti"`
	RefreshJTI          string    `json:"refresh_jti"`
	ConsumedRefreshJTIs []string  `json:"consumed_refresh_jtis,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// RotationStatus describes the result of an atomic refresh rotation.
type RotationStatus uint8

const (
	// RotationRejected means the presented token was not the current refresh
	// token for an active session.
	RotationRejected RotationStatus = iota
	// RotationSucceeded means the presented token was consumed and replaced.
	RotationSucceeded
	// RotationReused means the presented token had already been consumed. The
	// store revokes the whole session family before returning this status.
	RotationReused
)

// SessionStore persists active sessions and supports atomic refresh-token
// rotation. Implementations must make Rotate atomic: exactly one current
// refresh token may be consumed, and reuse of a consumed token must revoke the
// successor credentials.
type SessionStore interface {
	Create(ctx context.Context, session Session) error
	Get(ctx context.Context, id string) (Session, bool, error)
	Revoke(ctx context.Context, id string) error
	Rotate(ctx context.Context, id, presentedRefreshJTI string, next Session) (RotationStatus, error)
}

// MemorySessionStore is a small, process-local store useful for focused tests
// and single-process deployments. Production wiring uses RedisSessionStore so
// that sessions are shared by API replicas.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	now      func() time.Time
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]Session),
		now:      time.Now,
	}
}

func (s *MemorySessionStore) Create(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !session.ExpiresAt.After(s.now()) {
		return fmt.Errorf("session %s has already expired", session.ID)
	}
	s.sessions[session.ID] = cloneSession(session)
	return nil
}

func (s *MemorySessionStore) Get(_ context.Context, id string) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return Session{}, false, nil
	}
	if !session.ExpiresAt.After(s.now()) {
		delete(s.sessions, id)
		return Session{}, false, nil
	}
	return cloneSession(session), true, nil
}

func (s *MemorySessionStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	return nil
}

func (s *MemorySessionStore) Rotate(_ context.Context, id, presentedRefreshJTI string, next Session) (RotationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.sessions[id]
	if !ok {
		return RotationRejected, nil
	}
	if containsString(current.ConsumedRefreshJTIs, presentedRefreshJTI) {
		delete(s.sessions, id)
		return RotationReused, nil
	}
	if current.RefreshJTI != presentedRefreshJTI {
		return RotationRejected, nil
	}
	if !current.ExpiresAt.After(s.now()) {
		delete(s.sessions, id)
		return RotationRejected, nil
	}

	next.ID = current.ID
	next.UserID = current.UserID
	next.ExpiresAt = current.ExpiresAt
	next.ConsumedRefreshJTIs = append(current.ConsumedRefreshJTIs, presentedRefreshJTI)
	s.sessions[id] = cloneSession(next)
	return RotationSucceeded, nil
}

func cloneSession(session Session) Session {
	clone := session
	clone.ConsumedRefreshJTIs = append([]string(nil), session.ConsumedRefreshJTIs...)
	return clone
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
