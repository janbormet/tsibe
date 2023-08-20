package hash

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

func HashToG1(suite *pairing.SuiteBn256, data []byte) kyber.Point {
	return suite.G1().Point().(HashablePoint).Hash(data)
}

func HashToG2(suite *pairing.SuiteBn256, data []byte) kyber.Point {
	return suite.G2().Point().(HashablePoint).Hash(data)
}
