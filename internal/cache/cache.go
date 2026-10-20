package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// Cache envuelve un cliente Redis. Los errores de red se registran a nivel debug
// y no rompen el flujo — ante un Redis caído el servicio sólo pierde el hit rate.
type Cache struct {
	rdb     *redis.Client
	logger  *logrus.Logger
	timeout time.Duration
}

type Options struct {
	Addr     string
	Password string
	DB       int
	Logger   *logrus.Logger
}

func NewRedis(opts Options) (*Cache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         opts.Addr,
		Password:     opts.Password,
		DB:           opts.DB,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     20,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, err
	}

	return &Cache{
		rdb:     rdb,
		logger:  opts.Logger,
		timeout: 2 * time.Second,
	}, nil
}

func (c *Cache) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

func (c *Cache) Get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	val, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false
	}
	if err != nil {
		c.logger.WithError(err).WithField("key", key).Debug("redis GET falló")
		return nil, false
	}
	return val, true
}

func (c *Cache) Set(key string, value []byte, ttl time.Duration) {
	if c == nil || ttl <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		c.logger.WithError(err).WithField("key", key).Debug("redis SET falló")
	}
}

func (c *Cache) Invalidate(key string) {
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	_ = c.rdb.Del(ctx, key).Err()
}
