package core

import (
	"crypto/sha256"
	"time"
)

var Blockchains []*Blockchain

type Blockchain struct {
	Blocks         []Block
	Height         uint64
	GenesisBlock   *Block
	CandidateBlock *Block
}

/*
 This function creates a new blockchain.
*/
func CreateNewBlockchain() *Blockchain {
	block := CreateGenesisBlock()
	blockchain := &Blockchain{
		Blocks:         []Block{*block},
		Height:         1,
		GenesisBlock:   block,
		CandidateBlock: nil,
	}
	Blockchains = append(Blockchains, blockchain)
	return blockchain
}

/*
 This function creates a genesis block.
*/
func CreateGenesisBlock() *Block {
	block := &Block{
		//BlockSize:
		Header: BlockHeader{
			PreviousBlockHash: sha256.Sum256([]byte{}),
			//MerkleRoot:
			Timestamp: uint32(time.Now().UnixNano()),
			//Difficulty: 10,
			//Nonce:
			Index: 0,
		},
		//NumofTX:
		Transactions: nil,
	}
	return block
}

/*
 This function adds a block to a blockchain.
*/
func (blockchain *Blockchain) AddBlock() error {
	blockchain.Blocks = append(blockchain.Blocks, *blockchain.CandidateBlock)
	blockchain.Height = blockchain.Height + 1
	blockchain.CandidateBlock = nil
	return nil
}
