package ftkd

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"tsibe/hash"
)

type FKD struct {
	suite *pairing.SuiteBn256
	sk    kyber.Scalar
}

func NewRandomFKD(suite *pairing.SuiteBn256) *FKD {
	sk := suite.Scalar().Pick(suite.RandomStream())
	return &FKD{suite: suite, sk: sk}
}

func NewFKD(suite *pairing.SuiteBn256, sk kyber.Scalar) *FKD {
	return &FKD{suite: suite, sk: sk}
}

func (f FKD) DeriveWholeKey(left []byte, right []byte) kyber.Point {
	l := hash.HashToG1(f.suite, left)
	r := hash.HashToG2(f.suite, right)
	pt := f.suite.Pair(l, r)
	return pt.Mul(f.sk, pt)
}

func (f FKD) DeriveLeftKey(left []byte) kyber.Point {
	l := hash.HashToG1(f.suite, left)
	return l.Mul(f.sk, l)
}

func (f FKD) DeriveRightKey(right []byte) kyber.Point {
	r := hash.HashToG2(f.suite, right)
	return r.Mul(f.sk, r)
}

func (f FKD) DeriveFromLeftKey(left kyber.Point, right []byte) kyber.Point {
	r := hash.HashToG2(f.suite, right)
	return f.suite.Pair(left, r)
}

func (f FKD) DeriveFromRightKey(left []byte, right kyber.Point) kyber.Point {
	l := hash.HashToG1(f.suite, left)
	return f.suite.Pair(l, right)
}
