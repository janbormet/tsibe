package main_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"gonum.org/v1/gonum/stat/combin"
	"math"
	r "math/rand"
	"sync"
	"testing"
	"time"
	"tsibe/commit"
	"tsibe/hash"
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
	ns := []int{6, 12, 18}
	latencies := []time.Duration{1 * time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond}
	for _, n := range ns {
		for _, latency := range latencies {
			t1 := n / 3
			t2 := n / 2
			t3 := 2 * n / 3
			b.Run(fmt.Sprintf(":n=%d:t=%d:latency=%s", n, t1, latency.String()), func(b *testing.B) {
				benchEnc(b, t1, n, latency)
			})
			b.Run(fmt.Sprintf(":n=%d:t=%d:latency=%s", n, t2, latency.String()), func(b *testing.B) {
				benchEnc(b, t2, n, latency)
			})
			b.Run(fmt.Sprintf(":n=%d:t=%d:latency=%s", n, t3, latency.String()), func(b *testing.B) {
				benchEnc(b, t3, n, latency)
			})
		}
	}
}

func benchEnc(b *testing.B, t, n int, latency time.Duration) {
	sets := combin.Combinations(n, t)
	actualSets := make([][]int, b.N)
	for i := range actualSets {
		actualSets[i] = sets[r.Intn(len(sets))]
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
	wg := sync.WaitGroup{}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _ := e.Enc(senders[i], receivers[i], msgs[i], actualSets[i])
			ciphertexts[i] = c
		}(i)

	}
	wg.Wait()
	b.StopTimer()

	// Make sure the compiler doesn't optimize away the benchmark loop.
	for i := range ciphertexts {
		require.Equal(b, senders[i], ciphertexts[i].Sender)
	}
	// Verify correctness of results.
	// We comment it out for computing the actual benchmark results, because it significantly increases the benchmarking
	// time. It has no influence on the benchmark results.
	/*
		cor := make([]chan bool, b.N)
		for i := range cor {
			cor[i] = make(chan bool)
		}
		for i := range msgs {
			go func(i int) {
				key, err := e.DeriveIdentityKey(receivers[i], sets[0])
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
		}*/
}

func BenchmarkTSIBE_EncSingleServer(b *testing.B) {
	for par := 1; par <= 24; par++ {
		b.Run(fmt.Sprintf(":par=%d", par), func(b *testing.B) {
			simulateSingleServer(b, par)
		})
	}
}

func simulateSingleServer(b *testing.B, par int) {
	rIDs := make([][]byte, b.N)
	sIDs := make([][]byte, b.N)
	commitments := make([][]byte, b.N)
	right := make([][]byte, b.N)
	for i, _ := range rIDs {
		rIDs[i] = make([]byte, 4)
		_, err := rand.Read(rIDs[i])
		require.NoError(b, err)
		sIDs[i] = make([]byte, 4)
		_, err = rand.Read(sIDs[i])
		require.NoError(b, err)
		commitments[i] = make([]byte, 32)
		_, err = rand.Read(commitments[i])
		require.NoError(b, err)
		right[i] = make([]byte, 36)
		copy(right[i][:4], rIDs[i])
		copy(right[i][4:], commitments[i])
	}
	suite := pairing.NewSuiteBn256()
	poly := share.NewPriPoly(suite.GT(), 2, nil, suite.RandomStream())
	shares := poly.Shares(6)
	sk := shares[0]
	results := make([][]kyber.Point, par)
	parLeft := make([][][]byte, par)
	parRight := make([][][]byte, par)
	for i := range parLeft {
		start := i * (b.N / par)
		if i == par-1 {
			parLeft[i] = rIDs[start:]
			parRight[i] = right[start:]
			results[i] = make([]kyber.Point, b.N-start)
		} else {
			end := (i + 1) * (b.N / par)
			parLeft[i] = rIDs[start:end]
			parRight[i] = right[start:end]
			results[i] = make([]kyber.Point, end-start)
		}

	}
	b.ResetTimer()
	wg := sync.WaitGroup{}
	wg.Add(par)
	for i := 0; i < par; i++ {
		go func(i int) {
			for j := 0; j < len(parLeft[i]); j++ {
				le := hash.HashToG1(suite, parLeft[i][j])
				ri := hash.HashToG2(suite, parRight[i][j])
				pt := suite.Pair(le, ri)
				pt.Mul(sk.V, pt)
				results[i][j] = pt
			}
			wg.Done()
		}(i)

	}
	wg.Wait()
	b.StopTimer()
	sum := 0
	for i, resPar := range results {
		for j, res := range resPar {
			require.NotNil(b, res, fmt.Sprintf("i=%d,j=%d", i, j))
			sum += 1
		}
	}
	require.Equal(b, b.N, sum)
}

func BenchmarkTSIBE_DIdkSingleServer(b *testing.B) {
	for par := 1; par <= 24; par++ {
		b.Run(fmt.Sprintf(":par=%d", par), func(b *testing.B) {
			simulateSingleServerDIdk(b, par)
		})
	}
}

func simulateSingleServerDIdk(b *testing.B, par int) {
	ids := make([][]byte, b.N)
	for i, _ := range ids {
		ids[i] = make([]byte, 4)
		_, err := rand.Read(ids[i])
		require.NoError(b, err)
	}
	suite := pairing.NewSuiteBn256()
	poly := share.NewPriPoly(suite.GT(), 2, nil, suite.RandomStream())
	shares := poly.Shares(6)
	sk := shares[0]
	results := make([][]kyber.Point, par)
	parLeft := make([][][]byte, par)
	for i := range parLeft {
		start := i * (b.N / par)
		if i == par-1 {
			parLeft[i] = ids[start:]
			results[i] = make([]kyber.Point, b.N-start)
		} else {
			end := (i + 1) * (b.N / par)
			parLeft[i] = ids[start:end]
			results[i] = make([]kyber.Point, end-start)
		}

	}
	b.ResetTimer()
	wg := sync.WaitGroup{}
	wg.Add(par)
	for i := 0; i < par; i++ {
		go func(i int) {
			for j := 0; j < len(parLeft[i]); j++ {
				le := hash.HashToG1(suite, parLeft[i][j])
				le.Mul(sk.V, le)
				results[i][j] = le
			}
			wg.Done()
		}(i)

	}
	wg.Wait()
	b.StopTimer()
	sum := 0
	for i, resPar := range results {
		for j, res := range resPar {
			require.NotNil(b, res, fmt.Sprintf("i=%d,j=%d", i, j))
			sum += 1
		}
	}
	require.Equal(b, b.N, sum)
}

func BenchmarkTSIBE_Dec(b *testing.B) {
	c, m, rec, idk, suite := prepareCiphertexts(5000)
	for par := 1; par <= 24; par++ {
		b.Run(fmt.Sprintf(":par=%d", par), func(b *testing.B) {
			dec(b, par, suite, c[:b.N], m[:b.N], rec, idk)
		})
	}
}

func prepareCiphertexts(amt int) ([]tsibe.Ciphertext, [][]byte, int, kyber.Point, *pairing.SuiteBn256) {
	t := 2
	n := 3
	msgs := make([][]byte, amt)
	for i := range msgs {
		msgs[i] = make([]byte, 32)
		_, err := rand.Read(msgs[i])
		if err != nil {
			panic(err)
		}
	}
	senders := make([]int, amt)
	for i := range senders {
		senders[i] = r.Intn(math.MaxUint32)
	}
	receiver := 42
	sets := combin.Combinations(n, t)
	actualSets := make([][]int, amt)
	for i := range actualSets {
		actualSets[i] = sets[r.Intn(len(sets))]
	}
	e := tsibe.NewTSIBE(pairing.NewSuiteBn256(), t, n, 0)
	ciphertexts := make([]tsibe.Ciphertext, amt)
	wg := sync.WaitGroup{}
	for i := 0; i < amt; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _ := e.Enc(senders[i], receiver, msgs[i], actualSets[i])
			ciphertexts[i] = c
		}(i)
	}
	wg.Wait()
	idk, err := e.DeriveIdentityKey(receiver, sets[0])
	if err != nil {
		panic(err)
	}
	return ciphertexts, msgs, receiver, idk, e.Suite

}

func dec(b *testing.B, par int, s *pairing.SuiteBn256, ciphertexts []tsibe.Ciphertext, messages [][]byte, rec int, idk kyber.Point) {
	recBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(recBytes, uint32(rec))
	results := make([][][]byte, par)
	cPar := make([][]tsibe.Ciphertext, par)
	expected := make([][][]byte, par)
	for i := range cPar {
		start := i * (b.N / par)
		if i == par-1 {
			cPar[i] = ciphertexts[start:]
			expected[i] = messages[start:]
			results[i] = make([][]byte, b.N-start)
		} else {
			end := (i + 1) * (b.N / par)
			cPar[i] = ciphertexts[start:end]
			expected[i] = messages[start:end]
			results[i] = make([][]byte, end-start)
		}

	}

	wg := sync.WaitGroup{}
	wg.Add(par)
	b.ResetTimer()
	for i := 0; i < par; i++ {
		go func(i int) {
			for j, c := range cPar[i] {
				senBytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(senBytes, uint32(c.Sender))
				wk := deriveFromLeftKey(s, idk, append(senBytes, c.Commitment...))
				wkBytes, err := wk.MarshalBinary()
				if err != nil {
					panic(err)
				}
				mAndO := make([]byte, len(c.Gamma))
				s.XOF(wkBytes).XORKeyStream(mAndO, c.Gamma)
				m := mAndO[:len(c.Gamma)-256]
				o := mAndO[len(c.Gamma)-256:]
				cIn := make([]byte, len(m)+len(recBytes))
				copy(cIn[:len(m)], m)
				copy(cIn[len(m):], recBytes)
				if commit.Verify(s, c.Commitment, o, cIn) {
					results[i][j] = m
				} else {
					panic("invalid ciphertext")
				}
			}
			wg.Done()
		}(i)

	}
	wg.Wait()
	b.StopTimer()
	for i, resPar := range results {
		for j, res := range resPar {
			require.True(b, bytes.Equal(res, expected[i][j]), fmt.Sprintf("i=%d,j=%d", i, j))
		}
	}
}

func deriveFromLeftKey(suite *pairing.SuiteBn256, left kyber.Point, right []byte) kyber.Point {
	wk := hash.HashToG2(suite, right)
	return suite.Pair(left, wk)
}
