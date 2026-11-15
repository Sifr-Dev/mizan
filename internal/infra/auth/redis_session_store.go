package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisSessionKeyPrefix = "auth:session:"

// rotateSessionScript performs the refresh check and replacement in one Redis
// operation. A consumed refresh JTI deletes the whole session, invalidating the
// successor access and refresh tokens in the same family.
var rotateSessionScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 0
end

local session = cjson.decode(raw)
local consumed = session['consumed_refresh_jtis']
if consumed == nil then
  consumed = {}
end

if session['refresh_jti'] == ARGV[1] then
  session['access_jti'] = ARGV[2]
  session['refresh_jti'] = ARGV[3]
  session['role'] = ARGV[4]
  table.insert(consumed, ARGV[1])
  session['consumed_refresh_jtis'] = consumed
  redis.call('SET', KEYS[1], cjson.encode(session), 'PX', ARGV[5])
  return 1
end

for _, jti in ipairs(consumed) do
  if jti == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 2
  end
end

return 0
`)

// RedisSessionStore shares authentication sessions across API replicas.
type RedisSessionStore struct {
	client *redis.Client
	prefix string
}

func NewRedisSessionStore(client *redis.Client) *RedisSessionStore {
	return &RedisSessionStore{client: client, prefix: redisSessionKeyPrefix}
}

func (s *RedisSessionStore) key(id string) string {
	return s.prefix + id
}

func (s *RedisSessionStore) Create(ctx context.Context, session Session) error {
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("session %s has already expired", session.ID)
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	if err := s.client.Set(ctx, s.key(session.ID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) Get(ctx context.Context, id string) (Session, bool, error) {
	payload, err := s.client.Get(ctx, s.key(id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return Session{}, false, nil
		}
		return Session{}, false, fmt.Errorf("read session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return Session{}, false, fmt.Errorf("decode session: %w", err)
	}
	if !session.ExpiresAt.After(time.Now()) {
		_ = s.client.Del(ctx, s.key(id)).Err()
		return Session{}, false, nil
	}
	return session, true, nil
}

func (s *RedisSessionStore) Revoke(ctx context.Context, id string) error {
	if err := s.client.Del(ctx, s.key(id)).Err(); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) Rotate(ctx context.Context, id, presentedRefreshJTI string, next Session) (RotationStatus, error) {
	ttl := time.Until(next.ExpiresAt)
	if ttl <= 0 {
		return RotationRejected, nil
	}

	result, err := rotateSessionScript.Run(
		ctx,
		s.client,
		[]string{s.key(id)},
		presentedRefreshJTI,
		next.AccessJTI,
		next.RefreshJTI,
		next.Role,
		ttl.Milliseconds(),
	).Int()
	if err != nil {
		return RotationRejected, fmt.Errorf("rotate session: %w", err)
	}

	switch result {
	case 1:
		return RotationSucceeded, nil
	case 2:
		return RotationReused, nil
	default:
		return RotationRejected, nil
	}
}
