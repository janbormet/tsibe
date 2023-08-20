package hash

import "go.dedis.ch/kyber/v3"

type HashablePoint interface {
	Hash([]byte) kyber.Point
}
