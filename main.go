package main

import (
	"github.com/dooheeh/blockchain/core"
)

func main() {

	ws := core.CreateNewWallets()
	ws.AddWallet()
	ws.AddWallet()

	//...
}
