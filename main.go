package main

import (
	"github.com/blockchain/core"
)

func main() {

	ws := core.CreateNewWallets()
	ws.AddWallet()
	ws.AddWallet()

	//...
}
