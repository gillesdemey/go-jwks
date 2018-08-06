package jwks

import (
	"testing"
	"time"

	"github.com/bmizerany/assert"
)

func TestCreateProvider(t *testing.T) {
	t.Parallel()
	CreateProvider("http://localhost:3000/jwks", Options{
		timeout: 15 * time.Minute,
	})
}

func TestGetKey(t *testing.T) {
	t.Parallel()
	p := CreateProvider("http://localhost:3000/jwks", Options{
		timeout: 15 * time.Minute,
	})
	key, err := p.GetKey("app")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, key.KeyID, "app")
}
func TestGetKeyMemoized(t *testing.T) {
	t.Parallel()
	p := CreateProvider("http://localhost:3000/jwks", Options{
		timeout: 1 * time.Second,
	})

	key, _ := p.GetKey("app")
	key, _ = p.GetKey("app")
	key, _ = p.GetKey("app")

	time.Sleep(3 * time.Second)

	key, _ = p.GetKey("app")

	assert.Equal(t, key.KeyID, "app")
}
