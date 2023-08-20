package commit

import (
	"bytes"
	"go.dedis.ch/kyber/v3/pairing"
)

func Commit(suite *pairing.SuiteBn256, message []byte) (c []byte, o []byte) {
	o = make([]byte, 256)
	rng := suite.RandomStream()
	rng.XORKeyStream(o, o)
	in := make([]byte, len(message)+len(o))
	copy(in[:len(message)], message)
	copy(in[len(message):], o)
	h := suite.Hash()
	h.Reset()
	c = h.Sum(in)
	return c, o
}

func Verify(suite *pairing.SuiteBn256, c []byte, o []byte, m []byte) bool {
	in := make([]byte, len(m)+len(o))
	copy(in[:len(m)], m)
	copy(in[len(m):], o)
	h := suite.Hash()
	h.Reset()
	res := h.Sum(in)
	return bytes.Equal(res, c)
}
