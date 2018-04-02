package core

import (
	"crypto/sha256"
	"fmt"
	"time"
)

/*
 This function calculates a nonce that satisfies difficulty.
*/
func (blockchain *Blockchain) Mining() uint32 {
	diff := blockchain.CandidateBlock.Header.Difficulty
	fmt.Println("========== Proof of Work ==========")
	hash := sha256.Sum256(blockchain.CandidateBlock.Header.ToBytes())
	i := 1
	for ; CompareHash(hash, diff); hash, i = sha256.Sum256(blockchain.CandidateBlock.Header.ToBytes()), i+1 {
		blockchain.CandidateBlock.Header.Nonce = blockchain.CandidateBlock.Header.Nonce + 1
	}
	fmt.Printf("Try : %d\n", i)
	fmt.Printf("Difficulty : %d\n", diff)
	fmt.Printf("Block Hash : %x\n", hash)

	return blockchain.CandidateBlock.Header.Nonce
}

func CompareHash(hash [32]byte, diff uint32) bool {
	var count uint32
	count = 0
	for i := 0; i < 32; i++ {
		if hash[i] == 0 {
			count = count + 8
		} else if hash[i] == 1 {
			count = count + 7
			break
		} else if hash[i] <= 3 && hash[i] >= 2 {
			count = count + 6
			break
		} else if hash[i] <= 7 && hash[i] >= 4 {
			count = count + 5
			break
		} else if hash[i] <= 15 && hash[i] >= 8 {
			count = count + 4
			break
		} else if hash[i] <= 31 && hash[i] >= 16 {
			count = count + 3
			break
		} else if hash[i] <= 63 && hash[i] >= 32 {
			count = count + 2
			break
		} else if hash[i] <= 127 && hash[i] >= 64 {
			count = count + 1
			break
		} else {
			break
		}
	}
	if count >= diff {
		return false
	} else {
		return true
	}
}
