package shadowstream

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST SP 800-38A, sections F.5.1 and F.3.13 (CTR and CFB128).
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
func TestAESStreamKnownAnswers(t *testing.T) {
	decode := func(s string) []byte {
		p, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := decode("2b7e151628aed2a6abf7158809cf4f3c")
	plain := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		name, iv, encrypted string
		create              func([]byte) (Cipher, error)
	}{
		{"ctr", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", AESCTR},
		{"cfb", "000102030405060708090a0b0c0d0e0f", "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", AESCFB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.create(key)
			if err != nil {
				t.Fatal(err)
			}
			iv, want := decode(tc.iv), decode(tc.encrypted)
			got := make([]byte, len(plain))
			enc := c.Encrypter(iv)
			for start := 0; start < len(plain); {
				end := min(start+7, len(plain))
				enc.XORKeyStream(got[start:end], plain[start:end])
				start = end
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("ciphertext = %x", got)
			}
			dec := c.Decrypter(iv)
			for start := 0; start < len(got); {
				end := min(start+13, len(got))
				dec.XORKeyStream(got[start:end], got[start:end])
				start = end
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("plaintext = %x", got)
			}
		})
	}
}

func BenchmarkAESStream(b *testing.B) {
	for _, tc := range []struct {
		name   string
		create func([]byte) (Cipher, error)
	}{{"ctr", AESCTR}, {"cfb", AESCFB}} {
		b.Run(tc.name, func(b *testing.B) {
			c, err := tc.create(make([]byte, 16))
			if err != nil {
				b.Fatal(err)
			}
			s := c.Encrypter(make([]byte, c.IVSize()))
			buf := make([]byte, 16384)
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.XORKeyStream(buf, buf)
			}
		})
	}
}
