package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

var requestSequence atomic.Uint64

func requestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := fmt.Sprintf("%x-%x", time.Now().UnixNano(), requestSequence.Add(1))
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		log.Printf("request request_id=%s method=%s path=%s status=%d duration=%s", c.GetString("request_id"), c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(started).Round(time.Millisecond))
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

const proxyTokenHeader = "X-Tunnelfolio-Proxy-Token"

func loadProxyToken(path string) ([]byte, error) {
	if os.Geteuid() == 0 {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		for ancestor := filepath.Dir(absolute); ; ancestor = filepath.Dir(ancestor) {
			info, err := os.Lstat(ancestor)
			if err != nil {
				return nil, fmt.Errorf("inspect proxy token ancestor: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || ownerUID(info) != 0 || info.Mode().Perm()&0o022 != 0 {
				return nil, errors.New("proxy token ancestors must be root-owned directories not writable by group or world")
			}
			if ancestor == filepath.Dir(ancestor) {
				break
			}
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("proxy token must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("proxy token permissions %04o are too broad", info.Mode().Perm())
	}
	if os.Geteuid() == 0 && ownerUID(info) != 0 {
		return nil, errors.New("proxy token must be owned by root")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return nil, err
	}
	token := []byte(strings.TrimSpace(string(data)))
	if len(token) < 32 || len(token) > 256 {
		return nil, errors.New("proxy token must contain 32 to 256 non-whitespace bytes")
	}
	return token, nil
}

func requireTrustedProxy(expectedToken []byte, onReject func(*gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		providedToken := []byte(c.GetHeader(proxyTokenHeader))
		validToken := len(providedToken) == len(expectedToken) && subtle.ConstantTimeCompare(providedToken, expectedToken) == 1
		if !validToken || c.GetHeader("X-Forwarded-Proto") != "https" || strings.TrimSpace(c.GetHeader("X-Remote-User")) == "" || strings.TrimSpace(c.GetHeader("X-Forwarded-Host")) == "" {
			if onReject != nil {
				onReject(c)
			}
			writeError(c, http.StatusUnauthorized, "proxy_auth_required", "authenticated HTTPS reverse proxy required")
			c.Abort()
			return
		}
		c.Next()
	}
}

func validMutationOrigin(c *gin.Context, trustedProxy bool) bool {
	origin := c.GetHeader("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	expectedHost := c.Request.Host
	expectedScheme := "http"
	if trustedProxy {
		expectedHost = c.GetHeader("X-Forwarded-Host")
		expectedScheme = "https"
	}
	return parsed.Scheme == expectedScheme && sameHost(parsed.Host, expectedHost)
}

func sameHost(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr == nil && rightErr == nil {
		return strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
	}
	return strings.EqualFold(left, right)
}
