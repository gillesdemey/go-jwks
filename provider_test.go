package jwks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
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

func TestVerifySignature(t *testing.T) {
	t.Parallel()
	p := CreateProvider("http://localhost:3000/jwks", Options{
		timeout: 1 * time.Second,
	})

	key, err := p.GetKey("app")
	if err != nil {
		t.Fatal(err)
	}

	raw := `eyJhbGciOiJSUzI1NiIsImtpZCI6ImFwcCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.uTJN1FHYJc8C4cNONp2u_RWYeLVSwQOW5VxkuY051wL-aMvOqWtpUCJnu_Ny_3FLm-15vv6ppkKxWcp4buPUWYBKb9AuuS_BB7bRTUopgXZuGqBt6NxLKTIjfPWPQsMo9dKXoSzOroN7MHNAalcgWAcdpvgtF-aFfoktcsWtJVmMpyFWbDxywnuGEX9aaHZcB5Y0t-qj-3283fucU3om5SIhSy59UEbPSZvmncilLYGKCLlhezYp1AsFCAwZoQGUJQtnms-ElfT9ihLGWh4VhjgstI5NTY7yAIGBi4ndAjlhIm7OwLgU1MQysD4WSAUfcNLb872_QnZMpx7eIwe3SManlzQwzgKdidPGsnWIMB74xOE4AVQEcR710TNW8fkZdiwbgJc3K-cLJ_PWvUDYcZKzUZMNce7j63vndxoz33gfK5X0Rv6Qcrgh8vAxfZAYQzDuZ1MGmcoXVoDP9u1pT0fevIVayKjb6UZ6NNNXbC-Pug8S32CZICZI8GXm9JPGzdRtFpbVlrddqZ7KwmpQjiTsaI4Rf_mkvWuxSB3pCekIVAU75rV4StL_eMMd7pURhFX9indPV5HBXT4EHAiUkrqLBWAtH_E7i2ZFDcm1cNUJo_rd8K8EQCdPboQ8nvcU2RtypBliz7-qId6nfDJB6OxEekLL_iUQDZxtkLy7u3Y`
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.Claims{}
	if err := tok.Claims(key, &claims); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, claims.Issuer, "issuer")
	assert.Equal(t, claims.Subject, "subject")
}
