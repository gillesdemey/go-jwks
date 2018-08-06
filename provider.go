package jwks

import (
	"encoding/json"
	"net/http"
	"time"

	cache "github.com/patrickmn/go-cache"
	jose "gopkg.in/square/go-jose.v2"
)

var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

type Provider interface {
	GetKey(keyid string) (*jose.JSONWebKey, error)
	fetchKeys() (jose.JSONWebKeySet, error)
}

// Provider is the JWKS provider implementation
type DefaultProvider struct {
	endpoint string
	cache    *cache.Cache
}

type Options struct {
	timeout time.Duration
}

func CreateProvider(endpoint string, options Options) *DefaultProvider {
	return &DefaultProvider{
		endpoint: endpoint,
		cache:    cache.New(options.timeout, 15*time.Minute),
	}
}

func (p *DefaultProvider) GetKey(keyid string) (*jose.JSONWebKey, error) {
	_, expiration, found := p.cache.GetWithExpiration("jwks")
	if !found || expiration.Before(time.Now()) {
		keySet, err := p.fetchKeys()
		if err != nil {
			return nil, err
		}
		p.cache.SetDefault("jwks", &keySet)
	}

	jwks, found := p.cache.Get("jwks")
	if !found {
		return nil, nil
	}

	keys := jwks.(*jose.JSONWebKeySet).Key(keyid)
	if len(keys) == 0 {
		return nil, nil
	}

	return &keys[0], nil
}

func (p *DefaultProvider) fetchKeys() (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet

	response, err := httpClient.Get(p.endpoint)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer response.Body.Close()

	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		return jose.JSONWebKeySet{}, err
	}

	return set, nil
}
