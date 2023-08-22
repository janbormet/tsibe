module tsibe

go 1.21.0

require (
	github.com/stretchr/testify v1.3.0
	go.dedis.ch/kyber/v3 v3.1.0
	gonum.org/v1/gonum v0.14.0
)

require (
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.0.0-20190123085648-057139ce5d2b // indirect
	golang.org/x/sys v0.0.0-20190124100055-b90733256f2e // indirect
)

replace go.dedis.ch/kyber/v3 => github.com/janbormet/kyber/v3 v3.0.0-20230816164006-4b138bdaa87d
