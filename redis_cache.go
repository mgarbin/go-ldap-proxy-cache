package main

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/redis/go-redis/v9"
)

// RedisCache implements CacheInterface using Redis as the backend
type RedisCache struct {
	client *redis.Client
	ttl    time.Duration
	hits   uint64
	misses uint64
	ctx    context.Context
}

// NewRedisCache creates a new Redis-backed cache
func NewRedisCache(addr, password string, db int, ttl time.Duration) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	logger.Info().Str("addr", addr).Int("db", db).Msg("Successfully connected to Redis")

	return &RedisCache{
		client: client,
		ttl:    ttl,
		ctx:    ctx,
	}, nil
}

func (rc *RedisCache) Get(baseDN, filter string, attributes []string, scope int) (interface{}, bool) {
	key := generateCacheKey(baseDN, filter, attributes, scope)

	val, err := rc.client.Get(rc.ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist
		atomic.AddUint64(&rc.misses, 1)
		return nil, false
	} else if err != nil {
		// Other error
		logger.Error().Err(err).Msg("Redis GET error")
		atomic.AddUint64(&rc.misses, 1)
		return nil, false
	}

	// Deserialize the data to the correct type ([]*ldap.Entry)
	// This is the type that the proxy expects for LDAP search results
	var entries []*ldap.Entry
	if err := json.Unmarshal([]byte(val), &entries); err != nil {
		logger.Error().Err(err).Msg("Redis data unmarshal error")
		atomic.AddUint64(&rc.misses, 1)
		return nil, false
	}

	atomic.AddUint64(&rc.hits, 1)
	return entries, true
}

func (rc *RedisCache) Set(baseDN, filter string, attributes []string, scope int, data interface{}) {
	key := generateCacheKey(baseDN, filter, attributes, scope)

	// Serialize the data
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Error().Err(err).Msg("Redis data marshal error")
		return
	}

	// Set with TTL
	if err := rc.client.Set(rc.ctx, key, jsonData, rc.ttl).Err(); err != nil {
		logger.Error().Err(err).Msg("Redis SET error")
	}
}

func (rc *RedisCache) Stats() (hits, misses uint64, size int) {
	hits = atomic.LoadUint64(&rc.hits)
	misses = atomic.LoadUint64(&rc.misses)

	// Get approximate size (number of keys)
	// Note: DBSIZE returns the total number of keys in the selected Redis database,
	// not just keys created by this cache. If the Redis database is shared with
	// other applications or cache instances, this count will include all keys in the database.
	// For accurate cache-specific counts, consider using a key prefix and SCAN command,
	// or maintain a separate counter.
	dbSize, err := rc.client.DBSize(rc.ctx).Result()
	if err != nil {
		logger.Error().Err(err).Msg("Redis DBSIZE error")
		return hits, misses, 0
	}

	return hits, misses, int(dbSize)
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}
