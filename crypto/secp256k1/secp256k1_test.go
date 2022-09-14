package secp256k1_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	underlyingSecp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

type keyData struct {
	priv string
	pub  string
	addr string
}

var secpDataTable = []keyData{
	{
		priv: "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:  "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr: "FABB9CC6EC839B1214BB11C53377A56A6ED81762",
	},
}

func TestPubKeySecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrBbz, _ := hex.DecodeString(d.addr)
		addrB := crypto.Address(addrBbz)

		priv := secp256k1.PrivKey(privB)
		pubKey := priv.PubKey()
		pubT, _ := pubKey.(secp256k1.PubKey)
		pub := pubT
		addr := pubKey.Address()

		assert.Equal(t, pub, secp256k1.PubKey(pubB), "Expected pub keys to match")
		assert.Equal(t, addr, addrB, "Expected addresses to match")
	}
}

func TestSignAndValidateSecp256k1(t *testing.T) {
	privKey := secp256k1.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	assert.True(t, pubKey.VerifySignature(msg, sig))

	// Mutate the signature, just one bit.
	sig[3] ^= byte(0x01)

	assert.False(t, pubKey.VerifySignature(msg, sig))
}

// This test is intended to justify the removal of calls to the underlying library
// in creating the privkey.
func TestSecp256k1LoadPrivkeyAndSerializeIsIdentity(t *testing.T) {
	numberOfTests := 256
	for i := 0; i < numberOfTests; i++ {
		// Seed the test case with some random bytes
		privKeyBytes := [32]byte{}
		copy(privKeyBytes[:], crypto.CRandBytes(32))

		// This function creates a private and public key in the underlying libraries format.
		// The private key is basically calling new(big.Int).SetBytes(pk), which removes leading zero bytes
		priv, _ := underlyingSecp256k1.PrivKeyFromBytes(underlyingSecp256k1.S256(), privKeyBytes[:])
		// this takes the bytes returned by `(big int).Bytes()`, and if the length is less than 32 bytes,
		// pads the bytes from the left with zero bytes. Therefore these two functions composed
		// result in the identity function on privKeyBytes, hence the following equality check
		// always returning true.
		serializedBytes := priv.Serialize()
		require.Equal(t, privKeyBytes[:], serializedBytes)
	}
}

func TestGenPrivKeySecp256k1(t *testing.T) {
	// curve oder N
	N := underlyingSecp256k1.S256().N
	tests := []struct {
		name   string
		secret []byte
	}{
		{"empty secret", []byte{}},
		{
			"some long secret",
			[]byte("We live in a society exquisitely dependent on science and technology, " +
				"in which hardly anyone knows anything about science and technology."),
		},
		{"another seed used in cosmos tests #1", []byte{0}},
		{"another seed used in cosmos tests #2", []byte("mySecret")},
		{"another seed used in cosmos tests #3", []byte("")},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gotPrivKey := secp256k1.GenPrivKeySecp256k1(tt.secret)
			require.NotNil(t, gotPrivKey)
			// interpret as a big.Int and make sure it is a valid field element:
			fe := new(big.Int).SetBytes(gotPrivKey[:])
			require.True(t, fe.Cmp(N) < 0)
			require.True(t, fe.Sign() > 0)
		})
	}
}

func TestEthereumMessage(t *testing.T) {
	tests := []struct {
		msg []byte
		sig string
	}{
		{
			msg: []byte("my message"),
			sig: "6C5F939148250C526CCA7436DFA6B394C8195AD271FD88AA269D161C7642C3B74FEEB9E19F1821E89631F1375B1B00FCF9D6AD9CE29DFC4AF1B9E463C44AE9D01B",
		},
		{
			msg: []byte("hello world"),
			sig: "711A48DD85885160D68510E259C6DE72C1722D7B5AD6ADB2808E032299FB8DBE054444B125763AC0AF08952D9E091C35F44C90EC3524AFB45CE1AFFEC2D56FA31B",
		},
	}

	for _, test := range tests {
		privB, _ := hex.DecodeString(secpDataTable[0].priv)
		privKey := secp256k1.PrivKey(privB)
		pubKey := privKey.PubKey()

		sig, err := privKey.Sign(test.msg)
		tSig, _ := hex.DecodeString(test.sig)
		require.NoError(t, err)
		require.Equal(t, tSig, sig)

		require.True(t, pubKey.VerifySignature(test.msg, sig))
	}
}
