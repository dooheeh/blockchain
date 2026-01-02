# 블록체인 프로젝트 아키텍처 구성도

## 목차
1. [의존성 및 라이브러리 버전 맵](#1-의존성-및-라이브러리-버전-맵)
2. [상세 기술 스택](#2-상세-기술-스택)
3. [전체 시스템 아키텍처](#3-전체-시스템-아키텍처)
4. [외부 라이브러리 의존성 트리](#4-외부-라이브러리-의존성-트리)

---

## 1. 의존성 및 라이브러리 버전 맵

```mermaid
graph TB
    subgraph "프로젝트"
        Project["github.com/dooheeh/blockchain<br/>📦 Go 1.18+<br/>🏗️ 2017년 제작"]
    end

    subgraph "직접 의존성 (Direct Dependencies)"
        Base58["github.com/jbenet/go-base58<br/>📌 v0.0.0-20150317085156<br/>⚡ Base58 인코딩<br/>📄 Bitcoin-style addresses"]
        XCrypto["golang.org/x/crypto<br/>📌 v0.0.0-20220214200702<br/>⚡ RIPEMD-160 해싱<br/>📄 Extended crypto functions"]
    end

    subgraph "Go 표준 라이브러리 (Standard Library)"
        CryptoECDSA["crypto/ecdsa<br/>🔐 ECDSA P-256 서명<br/>📚 stdlib"]
        CryptoSHA["crypto/sha256<br/>🔐 SHA-256 해싱<br/>📚 stdlib"]
        CryptoRand["crypto/rand<br/>🔐 암호학적 난수<br/>📚 stdlib"]
        CryptoElliptic["crypto/elliptic<br/>🔐 타원곡선 P-256<br/>📚 stdlib"]
        EncodingBinary["encoding/binary<br/>📦 바이트 직렬화<br/>📚 stdlib"]
        Sync["sync<br/>🔒 Mutex 동시성 제어<br/>📚 stdlib"]
        Time["time<br/>⏰ 타임스탬프<br/>📚 stdlib"]
        Fmt["fmt<br/>📝 포맷 출력<br/>📚 stdlib"]
        Errors["errors<br/>❌ 에러 처리<br/>📚 stdlib"]
    end

    Project --> Base58
    Project --> XCrypto
    Project --> CryptoECDSA
    Project --> CryptoSHA
    Project --> CryptoRand
    Project --> CryptoElliptic
    Project --> EncodingBinary
    Project --> Sync
    Project --> Time
    Project --> Fmt
    Project --> Errors

    style Project fill:#e1bee7,stroke:#7b1fa2,stroke-width:3px
    style Base58 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style XCrypto fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style CryptoECDSA fill:#bbdefb,stroke:#1976d2,stroke-width:1px
    style CryptoSHA fill:#bbdefb,stroke:#1976d2,stroke-width:1px
    style CryptoRand fill:#bbdefb,stroke:#1976d2,stroke-width:1px
    style CryptoElliptic fill:#bbdefb,stroke:#1976d2,stroke-width:1px
    style EncodingBinary fill:#fff9c4,stroke:#f57f17,stroke-width:1px
    style Sync fill:#ffccbc,stroke:#e64a19,stroke-width:1px
    style Time fill:#d1c4e9,stroke:#512da8,stroke-width:1px
    style Fmt fill:#b2dfdb,stroke:#00796b,stroke-width:1px
    style Errors fill:#ffcdd2,stroke:#c62828,stroke-width:1px
```

## 2. 상세 기술 스택

```mermaid
graph LR
    subgraph "개발 환경"
        Lang["Go 1.18+<br/>Released: 2022-03"]
        Year["프로젝트 연도<br/>2017"]
    end

    subgraph "외부 라이브러리 (2개)"
        direction TB
        B58["go-base58<br/>━━━━━━━━━━<br/>버전: 6237cf65f3a6<br/>날짜: 2015-03-17<br/>━━━━━━━━━━<br/>기능: Base58 인코딩<br/>용도: 지갑 주소 생성<br/>파일: wallet.go:12,76"]
        XC["golang.org/x/crypto<br/>━━━━━━━━━━<br/>버전: 86341886e292<br/>날짜: 2022-02-14<br/>━━━━━━━━━━<br/>기능: RIPEMD-160<br/>용도: 공개키 해싱<br/>파일: wallet.go:13,88"]
    end

    subgraph "표준 라이브러리 (9개)"
        direction TB
        STD1["crypto/ecdsa<br/>ECDSA 서명/검증<br/>사용: transaction.go, wallet.go"]
        STD2["crypto/sha256<br/>SHA-256 해싱<br/>사용: 모든 파일"]
        STD3["crypto/rand<br/>암호학적 난수<br/>사용: wallet.go, mining.go"]
        STD4["crypto/elliptic<br/>P-256 타원곡선<br/>사용: transaction.go, wallet.go"]
        STD5["encoding/binary<br/>바이트 직렬화<br/>사용: block.go"]
        STD6["sync.RWMutex<br/>동시성 제어<br/>사용: blockchain.go, wallet.go"]
        STD7["time<br/>타임스탬프<br/>사용: blockchain.go, block.go"]
        STD8["fmt & errors<br/>출력 및 에러<br/>사용: 모든 파일"]
    end

    Lang --> B58
    Lang --> XC
    Lang --> STD1
    Lang --> STD2
    Lang --> STD3
    Lang --> STD4
    Lang --> STD5
    Lang --> STD6
    Lang --> STD7
    Lang --> STD8

    style Lang fill:#e1f5fe,stroke:#01579b,stroke-width:3px
    style Year fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    style B58 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style XC fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style STD1 fill:#e3f2fd,stroke:#1565c0,stroke-width:1px
    style STD2 fill:#e3f2fd,stroke:#1565c0,stroke-width:1px
    style STD3 fill:#e3f2fd,stroke:#1565c0,stroke-width:1px
    style STD4 fill:#e3f2fd,stroke:#1565c0,stroke-width:1px
    style STD5 fill:#fff8e1,stroke:#f57f17,stroke-width:1px
    style STD6 fill:#fce4ec,stroke:#c2185b,stroke-width:1px
    style STD7 fill:#f3e5f5,stroke:#7b1fa2,stroke-width:1px
    style STD8 fill:#e0f2f1,stroke:#00695c,stroke-width:1px
```

## 3. 전체 시스템 아키텍처

```mermaid
graph TB
    subgraph "Application Layer"
        Main[main.go<br/>진입점]
    end

    subgraph "Core Package - 핵심 블록체인 로직"
        BC[blockchain.go<br/>블록체인 관리]
        Block[block.go<br/>블록 구조]
        TX[transaction.go<br/>트랜잭션 처리]
        Wallet[wallet.go<br/>지갑 관리]
        Mining[mining.go<br/>채굴 알고리즘]
    end

    subgraph "External Libraries"
        Base58["go-base58<br/>📌 v0.0.0-20150317085156<br/>주소 인코딩"]
        RIPEMD["golang.org/x/crypto/ripemd160<br/>📌 v0.0.0-20220214200702<br/>주소 해싱"]
        Crypto["crypto/* (stdlib)<br/>ECDSA, SHA256, Rand"]
    end

    Main --> BC
    Main --> Wallet

    BC --> Block
    BC --> Mining
    BC --> TX

    Block --> TX
    Block --> Mining

    TX --> Wallet

    Wallet --> Base58
    Wallet --> RIPEMD
    Wallet --> Crypto

    TX --> Crypto
    Block --> Crypto
    Mining --> Crypto

    style Main fill:#e1f5ff
    style BC fill:#fff4e1
    style Block fill:#fff4e1
    style TX fill:#fff4e1
    style Wallet fill:#fff4e1
    style Mining fill:#fff4e1
    style Base58 fill:#e8f5e9
    style RIPEMD fill:#e8f5e9
    style Crypto fill:#e8f5e9
```

## 4. 외부 라이브러리 의존성 트리

```mermaid
graph TB
    subgraph "Application Code"
        WalletGo["wallet.go<br/>━━━━━━━━<br/>지갑 & 주소 생성"]
        TxGo["transaction.go<br/>━━━━━━━━<br/>트랜잭션 서명/검증"]
        BlockGo["block.go<br/>━━━━━━━━<br/>블록 해싱"]
        MiningGo["mining.go<br/>━━━━━━━━<br/>PoW 난수 생성"]
    end

    subgraph "External Dependencies"
        direction TB

        subgraph "go-base58 v0.0.0-20150317085156"
            Base58Encode["EncodeAlphabet()<br/>Bitcoin Base58 인코딩"]
            Base58Decode["DecodeAlphabet()<br/>Bitcoin Base58 디코딩"]
        end

        subgraph "golang.org/x/crypto v0.0.0-20220214200702"
            RIPEMD160["ripemd160.New()<br/>RIPEMD-160 해시 함수"]
        end

        subgraph "Go Standard Library (crypto/*)"
            ECDSA["crypto/ecdsa<br/>━━━━━━━━<br/>Sign()<br/>Verify()<br/>GenerateKey()"]
            SHA256["crypto/sha256<br/>━━━━━━━━<br/>Sum256()"]
            Rand["crypto/rand<br/>━━━━━━━━<br/>Reader<br/>Int()"]
            Elliptic["crypto/elliptic<br/>━━━━━━━━<br/>P256()"]
        end
    end

    WalletGo -->|"MakeAddress():77"| Base58Encode
    WalletGo -->|"Lock():258"| Base58Decode
    WalletGo -->|"PublickeyHash():88"| RIPEMD160
    WalletGo -->|"newKeypair():43"| ECDSA
    WalletGo -->|"newKeypair():42"| Elliptic
    WalletGo -->|"PublickeyHash():87"| SHA256

    TxGo -->|"Sign():109"| ECDSA
    TxGo -->|"Sign():109"| Rand
    TxGo -->|"Verify():169"| ECDSA
    TxGo -->|"Verify():143"| Elliptic
    TxGo -->|"CreateNewTransaction():101"| SHA256

    BlockGo -->|"CreateNewBlock():73"| SHA256
    BlockGo -->|"txhash():172"| SHA256

    MiningGo -->|"Mining():27"| Rand
    MiningGo -->|"Mining():33"| SHA256

    style WalletGo fill:#fff4e1,stroke:#f57c00,stroke-width:2px
    style TxGo fill:#fff4e1,stroke:#f57c00,stroke-width:2px
    style BlockGo fill:#fff4e1,stroke:#f57c00,stroke-width:2px
    style MiningGo fill:#fff4e1,stroke:#f57c00,stroke-width:2px

    style Base58Encode fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style Base58Decode fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style RIPEMD160 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px

    style ECDSA fill:#bbdefb,stroke:#1565c0,stroke-width:1px
    style SHA256 fill:#bbdefb,stroke:#1565c0,stroke-width:1px
    style Rand fill:#bbdefb,stroke:#1565c0,stroke-width:1px
    style Elliptic fill:#bbdefb,stroke:#1565c0,stroke-width:1px
```

## 5. 라이브러리 버전 및 사용 위치 상세

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'fontSize':'14px'}}}%%
timeline
    title 라이브러리 타임라인 및 버전 히스토리

    section 2015년
        go-base58 v6237cf6 : Bitcoin 주소 인코딩
                           : MIT License
                           : 마지막 업데이트 2015-03-17

    section 2017년
        블록체인 프로젝트 제작 : 대학 수업용
                               : Go 1.8~1.9 시대

    section 2022년
        golang.org/x/crypto v86341886 : RIPEMD-160 구현
                                      : BSD 3-Clause License
                                      : 업데이트 2022-02-14
        Go 1.18 릴리스 : Generics 도입
                      : 권장 버전
```

## 6. 파일별 라이브러리 사용 매트릭스

```mermaid
graph TD
    subgraph "사용 빈도 매트릭스"
        direction LR

        Files["📁 파일"]

        subgraph "wallet.go"
            W1["✅ go-base58 (2회)"]
            W2["✅ x/crypto (1회)"]
            W3["✅ crypto/ecdsa (1회)"]
            W4["✅ crypto/sha256 (1회)"]
            W5["✅ crypto/elliptic (1회)"]
            W6["✅ crypto/rand (1회)"]
        end

        subgraph "transaction.go"
            T1["✅ crypto/ecdsa (2회)"]
            T2["✅ crypto/sha256 (1회)"]
            T3["✅ crypto/elliptic (1회)"]
            T4["✅ crypto/rand (1회)"]
        end

        subgraph "block.go"
            B1["✅ crypto/sha256 (3회)"]
            B2["✅ encoding/binary (1회)"]
        end

        subgraph "mining.go"
            M1["✅ crypto/sha256 (2회)"]
            M2["✅ crypto/rand (1회)"]
        end

        subgraph "blockchain.go"
            BC1["✅ crypto/sha256 (1회)"]
        end
    end

    style W1 fill:#c8e6c9
    style W2 fill:#c8e6c9
    style W3 fill:#bbdefb
    style W4 fill:#bbdefb
    style W5 fill:#bbdefb
    style W6 fill:#bbdefb
    style T1 fill:#bbdefb
    style T2 fill:#bbdefb
    style T3 fill:#bbdefb
    style T4 fill:#bbdefb
    style B1 fill:#bbdefb
    style B2 fill:#fff9c4
    style M1 fill:#bbdefb
    style M2 fill:#bbdefb
    style BC1 fill:#bbdefb
```

## 7. 데이터 구조 관계도

```mermaid
classDiagram
    class Blockchain {
        +[]Block Blocks
        +uint64 Height
        +*Block GenesisBlock
        +*Block CandidateBlock
        +CreateNewBlockchain()
        +AddBlock()
        +Mining()
        +CreateNewTransaction()
        +FindUsableUTXO()
    }

    class Block {
        +BlockHeader Header
        +[]*Transaction Transactions
        +CreateNewBlock()
        +AddTransaction()
        +BlockVerification()
    }

    class BlockHeader {
        +[32]byte PreviousBlockHash
        +[32]byte MerkleRoot
        +uint32 Timestamp
        +uint32 Difficulty
        +uint32 Nonce
        +uint32 Index
        +ToBytes()
    }

    class Transaction {
        +[32]byte TXid
        +TXInput Vin
        +TXOutput Vout
        +string From
        +string To
        +Sign()
        +Verify()
        +ToBytes()
    }

    class TXInput {
        +[32]byte previousTXid
        +uint64 previousValue
        +[]byte ScriptSig
        +[]byte PublicKey
    }

    class TXOutput {
        +uint64 Value
        +[]byte ScriptPubKey
    }

    class Wallets {
        +map~string,*Wallet~ wallets
        +AddWallet()
        +GetWallet()
        +GetAddresses()
    }

    class Wallet {
        +ecdsa.PrivateKey PrivateKey
        +[]byte PublicKey
        +MakeAddress()
    }

    Blockchain "1" *-- "n" Block : contains
    Block "1" *-- "1" BlockHeader : has
    Block "1" *-- "n" Transaction : contains
    Transaction "1" *-- "1" TXInput : has
    Transaction "1" *-- "1" TXOutput : has
    Wallets "1" *-- "n" Wallet : manages
    Blockchain --> Transaction : creates
    Transaction --> Wallet : uses keys
```

## 3. 트랜잭션 생성 플로우

```mermaid
sequenceDiagram
    participant User
    participant Wallets
    participant Blockchain
    participant Transaction
    participant Wallet

    User->>Wallets: CreateNewWallets()
    User->>Wallets: AddWallet()
    Wallets->>Wallet: CreateNewWallet()
    Wallet->>Wallet: newKeypair() (ECDSA)
    Wallet->>Wallet: MakeAddress() (Base58)
    Wallet-->>Wallets: address
    Wallets-->>User: address

    User->>Blockchain: CreateNewTransaction(value, from, to)
    Blockchain->>Blockchain: FindUsableUTXO(value, from)
    Blockchain->>Transaction: Create TX object
    Transaction->>Transaction: Sign(privateKey)
    Transaction->>Transaction: Verify(signature, publicKey)
    Transaction-->>Blockchain: signed transaction
    Blockchain-->>User: transaction
```

## 4. 블록 생성 및 채굴 플로우

```mermaid
sequenceDiagram
    participant User
    participant Blockchain
    participant Block
    participant Mining
    participant Transaction

    User->>Blockchain: CreateNewBlockchain()
    Blockchain->>Block: CreateGenesisBlock()
    Block-->>Blockchain: genesis block
    Blockchain-->>User: blockchain

    User->>Block: CreateNewBlock(prevBlock, minerAddr)
    Block->>Transaction: CreateCoinbase(minerAddr)
    Transaction-->>Block: coinbase tx
    Block->>Block: AddTransaction(coinbase)
    Block->>Block: GenerateMerkleRoot()
    Block-->>User: new block

    User->>Blockchain: Set CandidateBlock
    User->>Blockchain: Mining()
    Blockchain->>Mining: CompareHash() loop
    Mining->>Mining: Increment nonce
    Mining->>Mining: SHA256(header)
    Mining-->>Blockchain: valid nonce

    User->>Blockchain: AddBlock()
    Blockchain->>Blockchain: Validate block
    Blockchain->>Blockchain: Append to chain
```

## 5. 모듈 간 의존성 맵

```mermaid
graph LR
    subgraph "main.go"
        M[Main Function]
    end

    subgraph "blockchain.go"
        BC1[CreateNewBlockchain]
        BC2[AddBlock]
        BC3[FindUsableUTXO]
        BC4[CreateNewTransaction]
    end

    subgraph "block.go"
        B1[CreateGenesisBlock]
        B2[CreateNewBlock]
        B3[AddTransaction]
        B4[GenerateMerkleRoot]
        B5[BlockVerification]
    end

    subgraph "transaction.go"
        T1[CreateCoinbase]
        T2[Sign]
        T3[Verify]
        T4[Lock]
    end

    subgraph "wallet.go"
        W1[CreateNewWallets]
        W2[AddWallet]
        W3[MakeAddress]
        W4[PublickeyHash]
    end

    subgraph "mining.go"
        MI1[Mining]
        MI2[CompareHash]
    end

    M --> BC1
    M --> W1
    M --> W2

    BC1 --> B1
    BC2 --> B5
    BC2 --> MI2
    BC3 --> T1
    BC4 --> T2
    BC4 --> T3
    BC4 --> T4

    B2 --> T1
    B3 --> B4

    T2 -.ECDSA.-> W4
    T3 -.ECDSA.-> W4
    T4 -.Base58.-> W4

    W2 --> W3
    W3 --> W4

    BC1 -.uses.-> MI1
    MI1 --> MI2

    style M fill:#e1f5ff
    style BC1 fill:#fff4e1
    style BC2 fill:#fff4e1
    style BC3 fill:#fff4e1
    style BC4 fill:#fff4e1
```

## 6. 암호화 기능 레이어

```mermaid
graph TB
    subgraph "Application Layer"
        TX[Transaction]
        Wallet[Wallet]
        Block[Block]
    end

    subgraph "Cryptographic Operations"
        ECDSA[ECDSA P-256<br/>Sign & Verify]
        SHA256[SHA-256<br/>Hashing]
        RIPEMD160[RIPEMD-160<br/>Address Hashing]
        Base58[Base58Check<br/>Encoding]
    end

    subgraph "Go Standard Library"
        CryptoECDSA[crypto/ecdsa]
        CryptoSHA[crypto/sha256]
        CryptoRand[crypto/rand]
    end

    subgraph "External Libraries"
        GoBase58[go-base58]
        XCryptoRIPEMD[golang.org/x/crypto/ripemd160]
    end

    TX --> ECDSA
    TX --> SHA256
    Wallet --> ECDSA
    Wallet --> SHA256
    Wallet --> RIPEMD160
    Wallet --> Base58
    Block --> SHA256

    ECDSA --> CryptoECDSA
    ECDSA --> CryptoRand
    SHA256 --> CryptoSHA
    RIPEMD160 --> XCryptoRIPEMD
    Base58 --> GoBase58

    style TX fill:#fff4e1
    style Wallet fill:#fff4e1
    style Block fill:#fff4e1
    style ECDSA fill:#ffe4e1
    style SHA256 fill:#ffe4e1
    style RIPEMD160 fill:#ffe4e1
    style Base58 fill:#ffe4e1
    style CryptoECDSA fill:#e8f5e9
    style CryptoSHA fill:#e8f5e9
    style CryptoRand fill:#e8f5e9
    style GoBase58 fill:#e8f5e9
    style XCryptoRIPEMD fill:#e8f5e9
```

## 7. UTXO 모델 데이터 흐름

```mermaid
graph LR
    subgraph "UTXO Pool"
        UTXO1[UTXO 1<br/>Value: 50]
        UTXO2[UTXO 2<br/>Value: 30]
        UTXO3[UTXO 3<br/>Value: 20]
    end

    subgraph "New Transaction"
        Input[TXInput<br/>previousTXid: UTXO1<br/>ScriptSig: signature]
        Output1[TXOutput<br/>Value: 30<br/>To: Bob]
        Output2[TXOutput<br/>Value: 20<br/>Change to Alice]
    end

    subgraph "Updated UTXO Pool"
        UTXO2_New[UTXO 2<br/>Value: 30]
        UTXO3_New[UTXO 3<br/>Value: 20]
        UTXO4_New[UTXO 4<br/>Value: 30<br/>Bob]
        UTXO5_New[UTXO 5<br/>Value: 20<br/>Alice]
    end

    UTXO1 -->|Spent| Input
    Input --> Output1
    Input --> Output2

    Output1 -->|Create| UTXO4_New
    Output2 -->|Create| UTXO5_New
    UTXO2 -.Unchanged.-> UTXO2_New
    UTXO3 -.Unchanged.-> UTXO3_New

    style UTXO1 fill:#ffcdd2
    style Input fill:#fff9c4
    style Output1 fill:#c8e6c9
    style Output2 fill:#c8e6c9
    style UTXO4_New fill:#a5d6a7
    style UTXO5_New fill:#a5d6a7
```

## 8. 파일별 주요 함수 및 책임

```mermaid
mindmap
  root((Blockchain Project))
    main.go
      Entry Point
      Demo Code
    blockchain.go
      CreateNewBlockchain
      CreateGenesisBlock
      AddBlock
      Global State Management
    block.go
      Block Structure
      BlockHeader
      CreateNewBlock
      AddTransaction
      GenerateMerkleRoot
      BlockVerification
    transaction.go
      Transaction Structure
      CreateNewTransaction
      Sign & Verify
      FindUsableUTXO
      CreateCoinbase
      UTXO Management
    wallet.go
      Wallet Structure
      CreateNewWallet
      newKeypair
      MakeAddress
      PublickeyHash
      Address Generation
    mining.go
      Mining Algorithm
      CompareHash
      Proof of Work
      Nonce Calculation
```

## 9. 비트코인 호환 레이어

```mermaid
graph TB
    subgraph "Bitcoin Compatibility"
        direction TB
        UTXO[UTXO Model<br/>transaction.go:175-213]
        Merkle[Merkle Tree<br/>block.go:136-166]
        PoW[Proof of Work<br/>mining.go:14-78]
        Address[Address Format<br/>wallet.go:69-105]
        Signature[ECDSA Signature<br/>transaction.go:108-170]
    end

    subgraph "Bitcoin Core Concepts"
        BUTXO[Bitcoin UTXO]
        BMerkle[Bitcoin Merkle Root]
        BPoW[Bitcoin SHA-256d]
        BAddress[Bitcoin Base58Check]
        BSignature[Bitcoin Signature]
    end

    UTXO -.Similar.-> BUTXO
    Merkle -.Identical.-> BMerkle
    PoW -.Simplified.-> BPoW
    Address -.Compatible.-> BAddress
    Signature -.Standard.-> BSignature

    style UTXO fill:#e3f2fd
    style Merkle fill:#e3f2fd
    style PoW fill:#e3f2fd
    style Address fill:#e3f2fd
    style Signature fill:#e3f2fd
    style BUTXO fill:#c8e6c9
    style BMerkle fill:#c8e6c9
    style BPoW fill:#c8e6c9
    style BAddress fill:#c8e6c9
    style BSignature fill:#c8e6c9
```

## 10. 동시성 제어 구조

```mermaid
graph TB
    subgraph "Global State"
        GlobalBC[var Blockchains []*Blockchain<br/>blockchain.go:12]
        GlobalMutex[var blockchainMutex sync.RWMutex<br/>blockchain.go:13]
    end

    subgraph "Blockchain Instance"
        BCBlocks[Blocks []Block]
        BCMutex[mu sync.RWMutex<br/>blockchain.go:21]
    end

    subgraph "Wallets Instance"
        WalletsMap[wallets map~string~*Wallet]
        WalletsMutex[mu sync.RWMutex<br/>wallet.go:21]
    end

    subgraph "Thread-Safe Operations"
        CreateBC[CreateNewBlockchain<br/>Lock: blockchainMutex]
        AddBlock[AddBlock<br/>Lock: bc.mu]
        AddWallet[AddWallet<br/>Lock: ws.mu]
        GetWallet[GetWallet<br/>RLock: ws.mu]
    end

    GlobalMutex -.Protects.-> GlobalBC
    BCMutex -.Protects.-> BCBlocks
    WalletsMutex -.Protects.-> WalletsMap

    CreateBC --> GlobalMutex
    AddBlock --> BCMutex
    AddWallet --> WalletsMutex
    GetWallet --> WalletsMutex

    style GlobalBC fill:#ffebee
    style GlobalMutex fill:#ffcdd2
    style BCBlocks fill:#fff9c4
    style BCMutex fill:#fff59d
    style WalletsMap fill:#e1f5fe
    style WalletsMutex fill:#81d4fa
```

---

## 다이어그램 렌더링 방법

이 다이어그램들은 Mermaid 문법으로 작성되었습니다. 다음 방법으로 시각화할 수 있습니다:

### 온라인 도구
1. **Mermaid Live Editor**: https://mermaid.live
   - 위 코드 블록을 복사하여 붙여넣기

2. **GitHub**:
   - 이 파일을 GitHub에 업로드하면 자동 렌더링

3. **VS Code**:
   - "Markdown Preview Mermaid Support" 확장 설치
   - 프리뷰 모드에서 확인

### CLI 도구
```bash
# Mermaid CLI 설치
npm install -g @mermaid-js/mermaid-cli

# PNG로 변환
mmdc -i ARCHITECTURE.md -o architecture.png
```

---

## 주요 인사이트

### 계층 구조
- **Application Layer**: main.go
- **Business Logic**: core 패키지 (5개 파일)
- **External Dependencies**: 2개 외부 라이브러리 + 9개 표준 라이브러리

### 의존성 방향
- 단방향 의존성 (순환 참조 없음)
- main → core → external libraries
- 외부 라이브러리는 경량 (총 2개만 사용)

### 핵심 상호작용
1. **blockchain.go** ↔ **block.go**: 블록 체인 관리
2. **block.go** ↔ **transaction.go**: 블록에 트랜잭션 포함
3. **transaction.go** ↔ **wallet.go**: 서명 및 검증
4. **blockchain.go** ↔ **mining.go**: PoW 수행

### 라이브러리 버전 정보

#### 외부 라이브러리
```
📦 github.com/jbenet/go-base58
   버전: v0.0.0-20150317085156-6237cf65f3a6
   릴리스: 2015년 3월 17일
   라이선스: MIT
   용도: Bitcoin 스타일 Base58Check 인코딩/디코딩
   사용 파일: wallet.go (2회 호출)

📦 golang.org/x/crypto
   버전: v0.0.0-20220214200702-86341886e292
   릴리스: 2022년 2월 14일
   라이선스: BSD 3-Clause
   용도: RIPEMD-160 해시 함수
   사용 파일: wallet.go (1회 호출)
```

#### Go 표준 라이브러리
```
🔐 crypto/ecdsa     - ECDSA P-256 디지털 서명
🔐 crypto/sha256    - SHA-256 해싱 (블록/트랜잭션 ID)
🔐 crypto/rand      - 암호학적 안전 난수 생성
🔐 crypto/elliptic  - P-256 타원곡선 연산
📦 encoding/binary  - 바이트 직렬화 (리틀 엔디안)
🔒 sync             - RWMutex 동시성 제어
⏰ time             - Unix 나노초 타임스탬프
📝 fmt              - 포맷 출력
❌ errors           - 에러 생성 및 처리
```

### 라이브러리 사용 통계

| 라이브러리 | 사용 파일 수 | 총 호출 횟수 | 주요 기능 |
|-----------|------------|------------|----------|
| crypto/sha256 | 5개 | 10회 | 블록 해싱, TX ID |
| crypto/ecdsa | 2개 | 4회 | 서명 생성/검증 |
| crypto/rand | 2개 | 3회 | Nonce, 키 생성 |
| go-base58 | 1개 | 2회 | 주소 인코딩 |
| crypto/elliptic | 2개 | 2회 | 키페어 생성 |
| x/crypto/ripemd160 | 1개 | 1회 | 주소 해싱 |
| encoding/binary | 1개 | 1회 | 블록 헤더 직렬화 |

### 프로젝트 메타데이터

```yaml
프로젝트명: github.com/dooheeh/blockchain
Go 버전: 1.18+ (권장)
제작 시기: 2017년
목적: 대학 블록체인 수업 교재
외부 의존성: 2개
표준 라이브러리: 9개
총 코드 파일: 6개 (main.go + core/*.go 5개)
라이선스: 명시되지 않음
```
