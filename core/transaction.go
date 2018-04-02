package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"time"

	b58 "github.com/jbenet/go-base58"
)

type Address string

type Transaction struct {
	TXid        [32]byte
	version     uint32
	Vin         TXInput
	Vout        TXOutput
	From        string
	To          string
	lockingTime uint64
}

type TXInput struct {
	previousTXid  [32]byte
	previousValue uint64
	ScriptSig     []byte
	PublicKey     []byte
}

type TXOutput struct {
	Value        uint64
	ScriptPubKey []byte
}

/*
 This function creates a new transaction.
*/
func (blockchain *Blockchain) CreateNewTransaction(value uint64, from string, to string, privKey ecdsa.PrivateKey, pubKey []byte) *Transaction {
	previous_tx := blockchain.FindUsableUTXO(value, from)
	signature := previous_tx.Sign(privKey)
	isVerify := previous_tx.Verify(signature, pubKey)

	if isVerify == false {
		return nil
	}

	tx := &Transaction{
		version: 0,
		Vin: TXInput{
			previousTXid:  previous_tx.TXid,
			previousValue: previous_tx.Vout.Value,
			ScriptSig:     signature,
			PublicKey:     pubKey,
		},
		Vout: TXOutput{
			Value:        value,
			ScriptPubKey: Lock(to),
		},
		From:        from,
		To:          to,
		lockingTime: uint64(time.Now().UnixNano()),
	}
	txid := make([]byte, 0)
	txid = append(txid, tx.ToBytes()...)
	tx.TXid = sha256.Sum256(txid)
	return tx
}

/*

 */
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey) []byte {
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, tx.TXid[:])
	if err != nil {

	}
	signature := append(r.Bytes(), s.Bytes()...)
	return signature[:]
}

/*

 */
func (tx *Transaction) Verify(signature []byte, pubKey []byte) bool {
	pubkeyHash := PublickeyHash(pubKey)

	if bytes.Compare(tx.Vout.ScriptPubKey, pubkeyHash) == 1 {
		return false
	}

	curve := elliptic.P256()

	r := big.Int{}
	s := big.Int{}
	SigLen := len(signature)
	r.SetBytes(signature[:(SigLen / 2)])
	s.SetBytes(signature[(SigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(pubKey)
	x.SetBytes(pubKey[:(keyLen / 2)])
	y.SetBytes(pubKey[(keyLen / 2):])

	PublicKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}

	if ecdsa.Verify(&PublicKey, tx.TXid[:], &r, &s) == true {
		return true
	} else {
		return false
	}
}

/*

 */
func (blockchain *Blockchain) FindUsableUTXO(value uint64, from string) *Transaction {
	var usable_UTXO map[string]*Transaction
	usable_UTXO = make(map[string]*Transaction)
	for i := 0; i < len(blockchain.Blocks); i++ {
		block := blockchain.Blocks[i]
		for _, tx := range block.Transactions {
			if strings.Compare(from, tx.From) == 0 {
				delete(usable_UTXO, string(tx.Vin.previousTXid[:]))
			} else if strings.Compare(from, tx.To) == 0 {
				usable_UTXO[string(tx.TXid[:])] = tx
			}
		}
	}

	var previous_tx *Transaction
	for _, val := range usable_UTXO {
		if val.Vout.Value >= value {
			previous_tx = val
			break
		}
	}
	if previous_tx == nil {
		return nil
	}

	return previous_tx
}

/*

 */
func CreateCoinbase(to string) *Transaction {
	tx := &Transaction{
		version: 0,
		Vin:     TXInput{},
		Vout: TXOutput{
			Value:        30,
			ScriptPubKey: Lock(to),
		},
		To:          to,
		lockingTime: uint64(time.Now().UnixNano()),
	}
	txid := make([]byte, 0)
	txid = append(txid, tx.ToBytes()...)
	tx.TXid = sha256.Sum256(txid)
	return tx
}

/*

 */
func Lock(addr string) []byte {
	pubkeyHash := b58.DecodeAlphabet(addr, b58.BTCAlphabet)
	pubkeyHash = pubkeyHash[1 : len(pubkeyHash)-4]
	return pubkeyHash
}

/*

 */
func (tx *Transaction) ToBytes() []byte {
	result := make([]byte, 0)
	result = append(result, tx.Vin.previousTXid[:]...)
	temp := make([]byte, 8)
	bitmask := uint64(0xff)
	for i := 0; i < len(temp); i++ {
		temp[i] = byte((tx.Vout.Value >> uint(56-(8*i))) & bitmask)
	}
	result = append(result, temp...)
	result = append(result, tx.Vout.ScriptPubKey[:]...)
	result = append(result, []byte(tx.From)...)
	result = append(result, []byte(tx.To)...)

	temp = make([]byte, 8)
	for i := 0; i < len(temp); i++ {
		temp[i] = byte((tx.lockingTime >> uint(56-(8*i))) & bitmask)
	}
	result = append(result, temp...)

	return result
}
