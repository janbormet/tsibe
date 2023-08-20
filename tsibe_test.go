package main_test

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"gonum.org/v1/gonum/stat/combin"
	"math"
	r "math/rand"
	"testing"
	"time"
	"tsibe/tsibe"
)

/*
func TestTSIBE(t *testing.T) {
	e := tsibe.NewTSIBE(pairing.NewSuiteBn256(), 7, 10, 100*time.Millisecond)
	c, err := e.Enc(3, 100, []byte("hello"), []int{0, 1, 2, 3, 6, 7, 8, 9})
	require.NoError(t, err)
	idk, err := e.DeriveIdentityKey(100, []int{1, 2, 3, 4, 6, 8, 9})
	require.NoError(t, err)
	m, err := e.Dec(idk, c)
	require.NoError(t, err)
	require.True(t, bytes.Equal(m, []byte("hello")))
}*/

func BenchmarkTSIBE_Enc(b *testing.B) {
	b.Run("latency=1 ms", func(b *testing.B) {
		benchEnc(b, 2, 6, 1*time.Millisecond)
	})
	b.Run("latency=10 ms", func(b *testing.B) {
		benchEnc(b, 2, 6, 10*time.Millisecond)
	})
	b.Run("latency=100 ms", func(b *testing.B) {
		benchEnc(b, 2, 6, 100*time.Millisecond)
	})
}

func benchEnc(b *testing.B, t, n int, latency time.Duration) {
	sets := make([][][]int, n-t+1)
	for i := range sets {
		sets[i] = combin.Combinations(n, i+t)
	}
	actualSets := make([][]int, b.N)
	for i := range actualSets {
		numberOfPartiesIndex := r.Intn(n - t + 1)
		combination := r.Intn(len(sets[numberOfPartiesIndex]))
		actualSets[i] = sets[numberOfPartiesIndex][combination]
	}
	e := tsibe.NewTSIBE(pairing.NewSuiteBn256(), t, n, latency)
	msgs := make([][]byte, b.N)
	for i := range msgs {
		msgs[i] = make([]byte, 32)
		_, err := rand.Read(msgs[i])
		require.NoError(b, err)
	}
	senders := make([]int, b.N)
	for i := range senders {
		senders[i] = i % 10
	}
	receivers := make([]int, b.N)
	for i := range receivers {
		receivers[i] = r.Intn(math.MaxUint32)
	}
	ciphertexts := make([]tsibe.Ciphertext, b.N)
	done := make([]chan struct{}, b.N)
	for i := range done {
		done[i] = make(chan struct{})
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		go func(i int) {
			c, _ := e.Enc(senders[i], receivers[i], msgs[i], actualSets[i])
			ciphertexts[i] = c
			close(done[i])
		}(i)

	}
	for i := range done {
		<-done[i]
	}
	b.StopTimer()

	cor := make([]chan bool, b.N)
	for i := range cor {
		cor[i] = make(chan bool)
	}
	for i := range msgs {
		go func(i int) {
			key, err := e.DeriveIdentityKey(receivers[i], sets[0][0])
			if err != nil {
				cor[i] <- false
				close(cor[i])
				return
			}
			res, err := e.Dec(key, ciphertexts[i])
			if err != nil {
				cor[i] <- false
				close(cor[i])
				return
			}
			if !bytes.Equal(res, msgs[i]) {
				cor[i] <- false
				close(cor[i])
				return
			}
			cor[i] <- true
			close(cor[i])
		}(i)
	}
	for i := range cor {
		x := <-cor[i]
		require.True(b, x)
	}
}

/*
func BenchmarkMultiEnc(b *testing.B) {
	e := tsibe.NewTSIBE(pairing.NewSuiteBn256(), 2, 6, 100*time.Millisecond)
	msgs := make([][]byte, 100)
	for i := range msgs {
		msgs[i] = make([]byte, 32)
		_, err := rand.Read(msgs[i])
		require.NoError(b, err)
	}
	b.StartTimer()
	ctxts, err := e.MultiEnc(0, 100, msgs, []int{0, 1})
	b.StopTimer()
	require.NoError(b, err)
	key, err := e.DeriveIdentityKey(100, []int{0, 1})
	require.NoError(b, err)
	for i := range msgs {
		res, err := e.Dec(key, ctxts[i])
		require.NoError(b, err)
		require.True(b, bytes.Equal(res, msgs[i]))
	}
}*/
