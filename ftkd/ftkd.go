package ftkd

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"time"
	"tsibe/hash"
)

type DLkChan struct {
	data []byte
	resp chan *share.PubShare
}

type DMultiWkChan struct {
	l    []byte
	r    [][]byte
	resp chan []*share.PubShare
}

type DWkChan struct {
	l    []byte
	r    []byte
	resp chan *share.PubShare
}

type Party struct {
	s        *pairing.SuiteBn256
	sk       *share.PriShare
	dLk      chan DLkChan
	dMultiWk chan DMultiWkChan
	dWk      chan DWkChan
}

type FTKD struct {
	Poly    *share.PriPoly
	Shares  []*share.PriShare
	Suite   *pairing.SuiteBn256
	t       int
	n       int
	parties []*Party
}

func NewFTKD(suite *pairing.SuiteBn256, t, n int, latency time.Duration) *FTKD {
	poly := share.NewPriPoly(suite.GT(), t, nil, suite.RandomStream())
	shares := poly.Shares(n)
	f := &FTKD{
		Poly:   poly,
		Shares: shares,
		Suite:  suite,
		t:      0,
		n:      0,
	}
	f.parties = make([]*Party, n)
	for i := range f.parties {
		p := Party{
			s:        suite,
			sk:       shares[i],
			dLk:      make(chan DLkChan, 1),
			dMultiWk: make(chan DMultiWkChan, 1),
			dWk:      make(chan DWkChan, 1),
		}
		f.parties[i] = &p
		go p.startParty(latency)
	}
	return f
}

func (f FTKD) DeriveLeftKey(left []byte, parties []int) (kyber.Point, error) {
	resp := make([]chan *share.PubShare, len(parties))
	for i, p := range parties {
		resp[i] = make(chan *share.PubShare)
		f.parties[p].dLk <- DLkChan{
			data: left,
			resp: resp[i],
		}
	}
	shares := make([]*share.PubShare, len(parties))
	for i := range resp {
		shares[i] = <-resp[i]
	}
	return share.RecoverCommit(f.Suite.G1(), shares, f.t, f.n)
}

func (f FTKD) DeriveLeftKeyRound2(left []byte, partyI int) *share.PubShare {
	l := hash.HashToG1(f.Suite, left)
	h := l.Mul(f.Shares[partyI].V, l)
	return &share.PubShare{
		I: partyI + 1,
		V: h,
	}
}

func (f FTKD) DeriveRightKeyRound2(right []byte, partyI int) *share.PubShare {
	r := hash.HashToG2(f.Suite, right)
	h := r.Mul(f.Shares[partyI].V, r)
	return &share.PubShare{
		I: partyI + 1,
		V: h,
	}
}

func (f FTKD) DeriveWholeKeyRound2(left []byte, right []byte, partyI int) *share.PubShare {
	l := hash.HashToG1(f.Suite, left)
	r := hash.HashToG2(f.Suite, right)
	pair := f.Suite.Pair(l, r)
	res := pair.Mul(f.Shares[partyI].V, pair)
	return &share.PubShare{
		I: partyI + 1,
		V: res,
	}
}

/*
func (f FTKD) DeriveRightKey(right []byte, parties []int) (kyber.Point, error) {
	shares := make([]*share.PubShare, len(parties))
	for i, p := range parties {
		shares[i] = f.DeriveRightKeyRound2(right, p)
	}
	return share.RecoverCommit(f.Suite.G2(), shares, f.t, f.n)
} */

func (f FTKD) DeriveWholeKey(left []byte, right []byte, parties []int) (kyber.Point, error) {
	resp := make([]chan *share.PubShare, len(parties))
	for i, p := range parties {
		resp[i] = make(chan *share.PubShare)
		f.parties[p].dWk <- DWkChan{
			l:    left,
			r:    right,
			resp: resp[i],
		}
	}
	shares := make([]*share.PubShare, len(parties))
	for i := range resp {
		shares[i] = <-resp[i]
	}
	return share.RecoverCommit(f.Suite.GT(), shares, f.t, f.n)
}

func (f FTKD) DeriveWholeKeys(left []byte, right [][]byte, parties []int) ([]kyber.Point, error) {
	resp := make([]chan []*share.PubShare, len(parties))
	for i, p := range parties {
		resp[i] = make(chan []*share.PubShare)
		f.parties[p].dMultiWk <- DMultiWkChan{
			l:    left,
			r:    right,
			resp: resp[i],
		}
	}
	shares := make([][]*share.PubShare, len(parties))
	for i := range resp {
		shares[i] = <-resp[i]
	}
	res := make([]kyber.Point, len(right))
	for i := range res {
		sharesI := make([]*share.PubShare, len(parties))
		for j := range sharesI {
			sharesI[j] = shares[j][i]
		}
		wk, err := share.RecoverCommit(f.Suite.GT(), sharesI, f.t, f.n)
		if err != nil {
			return nil, err
		}
		res[i] = wk
	}
	return res, nil
}

func (f FTKD) DeriveFromLeftKey(left kyber.Point, right []byte) kyber.Point {
	r := hash.HashToG2(f.Suite, right)
	return f.Suite.Pair(left, r)
}

/*
func (f FTKD) DeriveFromRightKey(left []byte, right kyber.Point) kyber.Point {
	l := hash.HashToG1(f.Suite, left)
	return f.Suite.Pair(l, right)
}*/

func (p Party) startParty(latency time.Duration) {
	for {
		select {
		case req := <-p.dLk:
			go func() {
				time.Sleep(latency)
				l := hash.HashToG1(p.s, req.data)
				h := l.Mul(p.sk.V, l)
				time.Sleep(latency)
				req.resp <- &share.PubShare{
					I: p.sk.I,
					V: h,
				}
			}()
		case req := <-p.dMultiWk:
			go func() {
				time.Sleep(latency)
				res := make([]*share.PubShare, len(req.r))
				for i := range res {
					e := p.s.Pair(hash.HashToG1(p.s, req.l), hash.HashToG2(p.s, req.r[i]))
					res[i] = &share.PubShare{
						I: p.sk.I,
						V: e.Mul(p.sk.V, e),
					}
				}
				time.Sleep(latency)
				req.resp <- res
			}()
		case req := <-p.dWk:
			go func() {
				time.Sleep(latency)
				e := p.s.Pair(hash.HashToG1(p.s, req.l), hash.HashToG2(p.s, req.r))
				h := e.Mul(p.sk.V, e)
				time.Sleep(latency)
				req.resp <- &share.PubShare{
					I: p.sk.I,
					V: h,
				}
			}()
		}
	}
}
