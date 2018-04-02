package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	b58 "github.com/jbenet/go-base58"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const LenofAddressCheckSum = 4

type Wallets struct {
	wallets map[string]*Wallet
}

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

/*

 */
func CreateNewWallets() *Wallets {
	ws := new(Wallets)
	ws.wallets = map[string]*Wallet{}
	return ws
}

/*
 This function creates a new transaction.
*/
func newKeypair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	prikey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {

	}
	pubkey := append(prikey.PublicKey.X.Bytes(), prikey.PublicKey.Y.Bytes()...)
	return *prikey, pubkey
}

/*
 This function creates a new wallet.
*/
func CreateNewWallet() *Wallet {
	prikey, pubkey := newKeypair()
	wallet := &Wallet{
		PrivateKey: prikey,
		PublicKey:  pubkey,
	}
	return wallet
}

/*

 */
func (w *Wallet) MakeAddress() string {
	pubkeyHash := PublickeyHash(w.PublicKey)
	firstPayload := append([]byte{version}, pubkeyHash...)
	secondPayload := append(firstPayload, checksum(firstPayload)...)
	address := b58.EncodeAlphabet(secondPayload, b58.BTCAlphabet)
	return address
}

/*

 */
func PublickeyHash(pubkey []byte) []byte {
	pubkeySHA256 := sha256.Sum256(pubkey)
	RIPEMD160 := ripemd160.New()
	_, err := RIPEMD160.Write(pubkeySHA256[:])
	if err != nil {
	}
	result := RIPEMD160.Sum(nil)
	return result
}

/*

 */
func checksum(payload []byte) []byte {
	First := sha256.Sum256(payload)
	Second := sha256.Sum256(First[:])

	return Second[:LenofAddressCheckSum]
}

/*

 */
func (ws *Wallets) AddWallet() string {
	wallet := CreateNewWallet()
	fmt.Print("Wallet is added to Wallets\n")
	address := wallet.MakeAddress()
	fmt.Print("Address of created wallet is :" + address + "\n")
	ws.wallets[address] = wallet

	return address
}

/*

 */
func (ws Wallets) GetWallet(address string) Wallet {
	return *ws.wallets[address]
}

/*

 */
func (ws *Wallets) GetAddresses() []string {
	var addresses []string

	for address := range ws.wallets {
		addresses = append(addresses, address)
	}

	return addresses
}
