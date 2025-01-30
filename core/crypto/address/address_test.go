package address

import (
	"math/rand"
	"testing"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	seed := rand.New(rand.NewSource(1234))
	pk, _, err := mldsa.GenerateKey(seed)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	//t.Logf("public key: %v\n", pk.Bytes())
	actual := "tl1rn5evt8jyynflgzq32plvrrgtve6zmu8ze4dvh"
	address, _ := New(pk)
	require.Equal(t, address.String(), actual)
}
