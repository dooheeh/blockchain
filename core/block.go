package core

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

/*
Block
*/
type Block struct {
	//BlockSize    uint32
	Header BlockHeader
	//NumofTX      []byte
	Transactions []*Transaction
}

/*
Block Header
*/
type BlockHeader struct {
	PreviousBlockHash [32]byte
	MerkleRoot        [32]byte
	Timestamp         uint32
	Difficulty        uint32
	Nonce             uint32
	Index             uint32
}

/*
 This function converts block header to byte slices.
*/
func (bh *BlockHeader) ToBytes() []byte {
	result := make([]byte, 0)
	result = append(result, bh.PreviousBlockHash[:]...)
	result = append(result, bh.MerkleRoot[:]...)

	for _, v := range []uint32{bh.Timestamp, bh.Difficulty, bh.Nonce, bh.Index} {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, v)
		result = append(result, buf...)
	}
	return result
}

/*
 This function creates a new block. And this block includes a transaction that gives reward to miner.
*/
func CreateNewBlock(prevBlock *Block, miner string) *Block {
	block := &Block{
		//BlockSize:
		Header: BlockHeader{
			PreviousBlockHash: sha256.Sum256(prevBlock.Header.ToBytes()),
			//MerkleRoot:
			Timestamp:  uint32(time.Now().UnixNano()),
			Difficulty: 4,
			//Nonce:
			Index: prevBlock.Header.Index + 1,
		},
		//NumofTX:
		Transactions: nil,
	}
	coinbase := CreateCoinbase(miner)
	block.AddTransaction(coinbase)

	return block
}

/*
 This function adds a transaction to a block.
*/
func (block *Block) AddTransaction(tx *Transaction) error {
	block.Transactions = append(block.Transactions, tx)
	buf := make([][]byte, 0)
	for _, t := range block.Transactions {
		buf = append(buf, t.TXid[:])
	}
	block.Header.MerkleRoot = GenerateMerkleRoot(buf)

	return nil
}

/*
 This function verifies that a nonce for a block is correct.
*/
func (block *Block) BlockVerification(nonce uint32) bool {
	block.Header.Nonce = nonce
	hash := sha256.Sum256(block.Header.ToBytes())
	result := !CompareHash(hash, block.Header.Difficulty)

	return result
}

/*
 This function calculates merkle root.
*/
func GenerateMerkleRoot(buf [][]byte) [32]byte {
	var NumofTX, i int
	txs := buf
	NumofTX = len(txs)

	for NumofTX > 1 {
		if NumofTX%2 == 1 {
			txs = append(txs, txs[NumofTX-1][:])
		}

		ParentNode := make([][]byte, 0)
		for i = 0; i < int(NumofTX/2); i++ {
			ParentNode = append(ParentNode, txhash(txs[2*i], txs[2*i+1]))
		}
		txs = ParentNode
		NumofTX = len(txs)
	}

	var result [32]byte
	copy(result[:], txs[0][:32])

	return result
}

func txhash(tx1, tx2 []byte) []byte {
	buf := make([]byte, 0)
	buf = append(buf, tx1[:]...)
	buf = append(buf, tx2[:]...)
	result := sha256.Sum256(buf)
	return result[:]
}
