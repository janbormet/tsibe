package ftkd_test

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"testing"
	"time"
	"tsibe/ftkd"
)

func TestFTKD(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	f := ftkd.NewFTKD(suite, 7, 10, 10*time.Millisecond)
	secret := f.Poly.Secret()
	fkd := ftkd.NewFKD(suite, secret)
	_ = fkd.DeriveLeftKey([]byte("hello"))
	lfFTKD, err := f.DeriveLeftKey([]byte("hello"), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)
	lfFTKDa, err := f.DeriveLeftKey([]byte("hello"), []int{0, 1, 3, 4, 5, 6, 7, 8})
	require.NoError(t, err)
	require.True(t, lfFTKD.Equal(lfFTKDa))

}

/*
func TestFTKD2(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	f := ftkd.NewFTKD(suite, 7, 10, 10*time.Millisecond)
	wk, err := f.DeriveWholeKey([]byte("hello"), []byte("world"), []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)
	lk, err := f.DeriveLeftKey([]byte("hello"), []int{0, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)
	rk, err := f.DeriveRightKey([]byte("world"), []int{1, 2, 4, 6, 7, 8, 9})
	require.NoError(t, err)
	wkFromLeft := f.DeriveFromLeftKey(lk, []byte("world"))
	_ = f.DeriveFromRightKey([]byte("hello"), rk)
	require.True(t, wk.Equal(wkFromLeft))
	//	require.True(t, wk.Equal(wkFromRight))
}*/

/*
func TestIntPow(t *testing.T) {
	require.Equal(t, 1024, ftkd.IntPow(2, 10))
	require.Equal(t, 1, ftkd.IntPow(11, 0))
}

func TestFTKDSetup(t *testing.T) {
	f := ftkd.NewFTKD(pairing.NewSuiteBn256())
	err := f.Setup(7, 10)
	require.NoError(t, err)
	fmt.Println(f.Parties)
}

func TestFTKDLagrange(t *testing.T) {
	f := ftkd.NewFTKD(pairing.NewSuiteBn256())
	err := f.Setup(7, 10)
	require.NoError(t, err)
	S := []int{1, 3, 4, 5, 7, 8, 9}
	li := make([]kyber.Scalar, len(S))
	for i := range S {
		li[i] = f.Parties[S[i]-1].LambdaI(S)
	}
	res := f.Suite.Scalar().Zero()
	for i := range li {
		si := f.Suite.Scalar().Mul(li[i], f.Parties[S[i]-1].Sk)
		res.Add(res, si)
	}
	require.Equal(t, f.S, res)
}

func TestZero(t *testing.T) {
	s := pairing.NewSuiteBn256()
	x := s.Scalar().Zero()
	y := s.Scalar().SetInt64(10)
	z := s.Scalar().Add(x, y)
	fmt.Println(z)
}

func TestPoly(t *testing.T) {
	f := ftkd.NewFTKD(pairing.NewSuiteBn256())
	err := f.Setup(7, 10)
	require.NoError(t, err)
}
*/
