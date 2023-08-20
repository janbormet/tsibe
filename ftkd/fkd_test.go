package ftkd_test

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"testing"
	"tsibe/ftkd"
)

func TestNewRandomFKD(t *testing.T) {
	f := ftkd.NewRandomFKD(pairing.NewSuiteBn256())
	wk := f.DeriveWholeKey([]byte("hello"), []byte("world"))
	lk := f.DeriveLeftKey([]byte("hello"))
	rk := f.DeriveRightKey([]byte("world"))
	wkFromLeft := f.DeriveFromLeftKey(lk, []byte("world"))
	wkFromRight := f.DeriveFromRightKey([]byte("hello"), rk)
	require.True(t, wk.Equal(wkFromLeft))
	require.True(t, wk.Equal(wkFromRight))
}
