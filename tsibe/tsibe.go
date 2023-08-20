package tsibe

import (
	"encoding/binary"
	"errors"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"time"
	"tsibe/commit"
	"tsibe/ftkd"
)

type Ciphertext struct {
	Receiver   int
	Sender     int
	Commitment []byte
	Gamma      []byte
}

type TSIBE struct {
	Suite *pairing.SuiteBn256
	F     *ftkd.FTKD
}

type Timer struct {
	start time.Time
	end   time.Time
}

func NewTSIBE(suite *pairing.SuiteBn256, t, n int, latency time.Duration) *TSIBE {
	return &TSIBE{
		Suite: suite,
		F:     ftkd.NewFTKD(suite, t, n, latency),
	}
}

func (t TSIBE) Enc(sender int, receiver int, m []byte, S []int) (Ciphertext, error) {
	rec := make([]byte, 4)
	sen := make([]byte, 4)
	binary.LittleEndian.PutUint32(rec, uint32(receiver))
	binary.LittleEndian.PutUint32(sen, uint32(sender))
	cIn := make([]byte, len(m)+len(rec))
	copy(cIn[:len(m)], m)
	copy(cIn[len(m):], rec)
	d, o := commit.Commit(t.Suite, cIn)
	wk, err := t.F.DeriveWholeKey(rec, append(sen, d...), S)
	if err != nil {
		return Ciphertext{}, err
	}
	wkBytes, err := wk.MarshalBinary()
	if err != nil {
		return Ciphertext{}, err
	}
	gamma := make([]byte, len(m)+len(o))
	xOrIn := make([]byte, len(m)+len(o))
	copy(xOrIn[:len(m)], m)
	copy(xOrIn[len(m):], o)
	t.Suite.XOF(wkBytes).XORKeyStream(gamma, xOrIn)
	return Ciphertext{
		Receiver:   receiver,
		Sender:     sender,
		Commitment: d,
		Gamma:      gamma,
	}, nil
}

func (t TSIBE) DeriveIdentityKey(id int, S []int) (kyber.Point, error) {
	idBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(idBytes, uint32(id))
	return t.F.DeriveLeftKey(idBytes, S)
}

func (t TSIBE) Dec(idk kyber.Point, c Ciphertext) ([]byte, error) {
	recBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(recBytes, uint32(c.Receiver))
	senBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(senBytes, uint32(c.Sender))
	wk := t.F.DeriveFromLeftKey(idk, append(senBytes, c.Commitment...))
	wkBytes, err := wk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mAndO := make([]byte, len(c.Gamma))
	t.Suite.XOF(wkBytes).XORKeyStream(mAndO, c.Gamma)
	m := mAndO[:len(c.Gamma)-256]
	o := mAndO[len(c.Gamma)-256:]
	cIn := make([]byte, len(m)+len(recBytes))
	copy(cIn[:len(m)], m)
	copy(cIn[len(m):], recBytes)
	if commit.Verify(t.Suite, c.Commitment, o, cIn) {
		return m, nil
	}
	return nil, errors.New("invalid ciphertext")
}

func (t TSIBE) MultiEnc(sender int, receiver int, m [][]byte, S []int) ([]Ciphertext, error) {
	rec := make([]byte, 4)
	sen := make([]byte, 4)
	binary.LittleEndian.PutUint32(rec, uint32(receiver))
	binary.LittleEndian.PutUint32(sen, uint32(sender))
	ctxts := make([]Ciphertext, len(m))
	cins := make([][]byte, len(m))
	ds := make([][]byte, len(m))
	os := make([][]byte, len(m))
	rights := make([][]byte, len(m))
	for i := range cins {
		cins[i] = make([]byte, len(m[i])+len(rec))
		copy(cins[i][:len(m[i])], m[i])
		copy(cins[i][len(m[i]):], rec[:])
		d, o := commit.Commit(t.Suite, cins[i])
		ds[i] = d
		os[i] = o
		rights[i] = make([]byte, len(sen)+len(d))
		copy(rights[i][:len(sen)], sen)
		copy(rights[i][len(sen):], d)
	}
	wks, err := t.F.DeriveWholeKeys(rec, rights, S)
	if err != nil {
		return nil, err
	}
	for i := range ctxts {
		wkBytes, err := wks[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		gamma := make([]byte, len(m[i])+len(os[i]))
		xOrIn := make([]byte, len(m[i])+len(os[i]))
		copy(xOrIn[:len(m)], m[i])
		copy(xOrIn[len(m):], os[i])
		t.Suite.XOF(wkBytes).XORKeyStream(gamma, xOrIn)
		ctxts[i] = Ciphertext{
			Receiver:   receiver,
			Sender:     sender,
			Commitment: ds[i],
			Gamma:      gamma,
		}

	}
	return ctxts, nil
}
