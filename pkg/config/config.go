package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Auth    AuthConfig
	Booking BookingConfig
	Logger  LoggerConfig
}
type AuthConfig struct {
	Handler    HandlerConfig
	AuthServer AuthServerConfig

	DB AuthDBConfig

	JWT    AuthJWTConfig
	Argon2 AuthArgon2Config
	SHA256 SHA256Config
}
type HandlerConfig struct {
	TimeContextInSecond int
	RefreshTTLDays      int
}
type AuthServerConfig struct {
	Port string
}
type AuthDBConfig struct {
	DSN string
}

type AuthJWTConfig struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	AccessTTLMinutes int
	RefreshTTLDays   int
	Issuer           string
}

type AuthArgon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32

	Pepper string
}

type SHA256Config struct {
	Salt []byte
}

type BookingConfig struct {
	BookingDBConfig
}

type BookingDBConfig struct {
	DSN string
}
type LoggerConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env")
	return &Config{
		Auth: AuthConfig{
			Handler: HandlerConfig{
				TimeContextInSecond: getEnvAsInt("TimeContextInSecond", 15),
				RefreshTTLDays:      getEnvAsInt("AUTH_JWT_REFRESH_TTL_DAYS", 30),
			},
			AuthServer: AuthServerConfig{
				Port: getEnv("AUTH_SERVER_PORT", "8081"),
			},
			DB: AuthDBConfig{
				DSN: getEnv("AUTH_DB_DSN", ""),
			},
			JWT: AuthJWTConfig{
				PrivateKey:       loadPrivateKey(getEnv("JWT_PRIVATE_KEY_PATH", "keys/private.pem")),
				PublicKey:        loadPublicKey(getEnv("JWT_PUBLIC_KEY_PATH", "keys/public.pem")),
				AccessTTLMinutes: getEnvAsInt("AUTH_JWT_ACCESS_TTL_MINUTE", 15),
				RefreshTTLDays:   getEnvAsInt("AUTH_JWT_REFRESH_TTL_DAYS", 30),
				Issuer:           getEnv("AUTH_JWT_ISSUER", "auth_service"),
			},
			Argon2: AuthArgon2Config{
				Iterations:  getEnvAsUint32("AUTH_ARGON2_TIME", 1),
				Memory:      getEnvAsUint32("AUTH_ARGON2_MEMORY", 64*1024),
				Parallelism: getEnvAsUint8("AUTH_ARGON2_THREADS", 4),
				SaltLength:  getEnvAsUint32("AUTH_ARGON2_SALT_LEN", 32),
				KeyLength:   getEnvAsUint32("AUTH_ARGON2_KEY_LEN", 32),

				Pepper: getEnv("AUTH_ARGON2_PEPPER", ""),
			},
			SHA256: SHA256Config{
				Salt: getEnvAsBase64("AUTH_SHA256_SALT", nil),
			},
		},
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if parsed, err := strconv.ParseInt(value, 10, strconv.IntSize); err == nil {
			return int(parsed)
		}
	}
	return defaultValue
}

func getEnvAsUint32(key string, defaultValue uint32) uint32 {
	if value, exists := os.LookupEnv(key); exists {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint32(parsed)
		}
	}
	return defaultValue
}

func getEnvAsUint8(key string, defaultValue uint8) uint8 {
	if value, exists := os.LookupEnv(key); exists {
		if parsed, err := strconv.ParseUint(value, 10, 8); err == nil {
			return uint8(parsed)
		}
	}
	return defaultValue
}

func getEnvAsBase64(key string, defaultValue []byte) []byte {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		return nil
	}

	if b, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(value); err == nil {
		return b
	}
	return defaultValue
}

func loadPrivateKey(path string) *rsa.PrivateKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		panic(fmt.Errorf("failed to decode PEM block from %s", path))
	}

	// PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key
	}

	// PKCS#8
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		panic(fmt.Errorf("not RSA private key in %s", path))
	}

	return key
}

func loadPublicKey(path string) *rsa.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		panic(fmt.Errorf("failed to decode PEM block from %s", path))
	}

	// PKCS#1 public
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key
	}

	// PKIX public
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		panic(fmt.Errorf("not RSA public key in %s", path))
	}

	return pub
}
