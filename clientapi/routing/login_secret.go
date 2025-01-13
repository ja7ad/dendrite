package routing

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/element-hq/dendrite/internal"
	"github.com/matrix-org/util"
	cache "github.com/patrickmn/go-cache"
)

type SharedSecretLoginRequest struct {
	User     string `json:"username"`
	Nonce    string `json:"nonce"`
	MacBytes []byte
	MacStr   string `json:"mac"`
}

func NewSharedSecretLoginRequest(reader io.ReadCloser) (*SharedSecretLoginRequest, error) {
	defer internal.CloseAndLogIfError(context.Background(), reader, "NewSharedSecretLoginRequest: failed to close request body")
	var sslr SharedSecretLoginRequest
	err := json.NewDecoder(reader).Decode(&sslr)
	if err != nil {
		return nil, err
	}
	sslr.MacBytes, err = hex.DecodeString(sslr.MacStr)
	return &sslr, err
}

type SharedSecretLogin struct {
	sharedSecret string
	nonces       *cache.Cache
}

func NewSharedSecretLogin(sharedSecret string) *SharedSecretLogin {
	return &SharedSecretLogin{
		sharedSecret: sharedSecret,
		// nonces live for 5mins, purge every 10mins
		nonces: cache.New(5*time.Minute, 10*time.Minute),
	}
}

func (r *SharedSecretLogin) GenerateNonce() string {
	nonce := util.RandomString(16)
	r.nonces.Set(nonce, true, cache.DefaultExpiration)
	return nonce
}

func (r *SharedSecretLogin) validNonce(nonce string) bool {
	_, exists := r.nonces.Get(nonce)
	return exists
}

func (r *SharedSecretLogin) IsValidMacLogin(
	nonce, username string, givenMac []byte,
) (bool, error) {
	// Check that shared secret login isn't disabled.
	if r.sharedSecret == "" {
		return false, errors.New("shared secret login is disabled")
	}
	if !r.validNonce(nonce) {
		return false, fmt.Errorf("incorrect or expired nonce: %s", nonce)
	}

	// Check that username/password don't contain the HMAC delimiters.
	if strings.Contains(username, "\x00") {
		return false, errors.New("username contains invalid character")
	}

	joined := strings.Join([]string{nonce, username}, "\x00")

	mac := hmac.New(sha1.New, []byte(r.sharedSecret))
	_, err := mac.Write([]byte(joined))
	if err != nil {
		return false, err
	}
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(givenMac, expectedMAC), nil
}
