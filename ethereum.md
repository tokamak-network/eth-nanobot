# Ethereum Tool

nanobot에서 Ethereum 블록체인과 상호작용하기 위한 도구.

LLM이 직접 잔액 조회, ETH 전송, 스마트 컨트랙트 호출 등을 수행할 수 있다. 개인키는 Tool 내부에서만 관리되며 LLM에 절대 노출되지 않는다.

## 설치

```bash
pip install nanobot-ai[ethereum]
```

또는 기존 환경에 패키지 추가:

```bash
pip install web3 cryptography
```

## 초기 설정

### 대화형 설정 (권장)

```bash
nanobot ethereum init
```

순서:
1. Seed phrase 입력 (12/24 단어)
2. 암호화 패스워드 설정
3. 네트워크 선택 (Localhost / Sepolia / Mainnet / Custom)

실행 결과:
- `~/.nanobot/ethereum/seed.enc` — 암호화된 seed 파일 생성
- `~/.nanobot/config.json` — ethereum 설정 활성화

### config.json 직접 편집

```json
{
  "tools": {
    "ethereum": {
      "enabled": true,
      "rpcUrl": "http://127.0.0.1:8545",
      "chainId": 31337,
      "accountIndex": 0,
      "seedFile": "~/.nanobot/ethereum/seed.enc",
      "abisDir": "~/.nanobot/workspace/ethereum/abis",
      "gasLimit": 300000,
      "confirmations": 1
    }
  }
}
```

| 필드 | 기본값 | 설명 |
|------|--------|------|
| `enabled` | `false` | Tool 활성화 여부 |
| `rpcUrl` | `http://127.0.0.1:8545` | JSON-RPC 엔드포인트 |
| `chainId` | `31337` | 네트워크 Chain ID |
| `accountIndex` | `0` | HD wallet 계정 인덱스 (BIP-44) |
| `seedFile` | `~/.nanobot/ethereum/seed.enc` | 암호화된 seed 파일 경로 |
| `abisDir` | `~/.nanobot/workspace/ethereum/abis` | ABI 파일 디렉토리 |
| `gasLimit` | `300000` | 트랜잭션 최대 가스 |
| `confirmations` | `1` | 트랜잭션 확인 대기 수 |

## 계정 (키) 관리

### Seed Phrase 로딩 우선순위

Tool 시작 시 아래 순서로 계정을 로드한다:

1. **환경변수 `ETH_MNEMONIC`** — 있으면 바로 사용 (파일 무시)
2. **암호화 파일 `seed.enc`** + 환경변수 `ETH_SEED_PASSWORD` — 패스워드로 복호화
3. **둘 다 없으면** — 읽기 전용 모드 (잔액 조회, 블록 조회만 가능)

### 환경변수 방식 (테스트/CI용)

```bash
# Hardhat 기본 seed로 실행
ETH_MNEMONIC="test test test test test test test test test test test junk" nanobot agent

# 게이트웨이에도 동일 적용
ETH_MNEMONIC="test test test test test test test test test test test junk" nanobot gateway
```

### 암호화 파일 방식

```bash
# 1. init으로 seed 암호화 저장
nanobot ethereum init

# 2. 패스워드를 환경변수로 제공하여 실행
ETH_SEED_PASSWORD="mypassword" nanobot gateway
```

암호화 방식:
- **알고리즘**: Fernet 대칭 암호화
- **키 파생**: PBKDF2-HMAC-SHA256 (480,000 iterations)
- **저장 포맷**: JSON (`{"salt": "...", "data": "..."}`)

### HD Wallet 파생 경로

BIP-44 표준: `m/44'/60'/0'/0/{index}`

하나의 seed에서 무제한 계정을 파생할 수 있다:
- config의 `accountIndex`는 **기본 계정** 인덱스 (시작 시 로드)
- tool 호출 시 `account_index` 파라미터로 **런타임에 다른 계정 선택** 가능

Hardhat 기본 seed (`test test ... junk`)의 주요 계정:

| Index | Address |
|-------|---------|
| 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |
| 2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` |
| 3 | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` |
| 4 | `0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65` |

## CLI 명령어

```bash
# 초기 설정 (seed + 네트워크)
nanobot ethereum init

# 연결 상태, 계정 주소, 잔액 확인
nanobot ethereum status

# 네트워크 설정 상세 보기
nanobot ethereum networks
```

### `nanobot ethereum status` 출력 예시

```
Ethereum Status
──────────────────────────────
Enabled: ✓
RPC URL: http://127.0.0.1:8545
Chain ID: 31337
Account Index: 0
Connected: ✓
Latest Block: 5
Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Balance: 9998.499 ETH
```

## Tool Actions

LLM은 `ethereum` tool을 다음 8가지 action으로 호출한다.

모든 action에 공통으로 사용 가능한 파라미터:

| 파라미터 | 타입 | 설명 |
|----------|------|------|
| `account_index` | integer (선택) | HD wallet 계정 인덱스. 생략 시 config 기본값 사용. 같은 seed에서 다른 계정으로 전환할 때 사용 |

### get_balance

ETH 잔액 조회. `address`와 `account_index` 모두 생략 시 기본 계정.

```json
// 기본 계정 잔액
{"action": "get_balance"}

// 특정 주소 잔액
{"action": "get_balance", "address": "0x..."}

// 특정 인덱스 계정 잔액
{"action": "get_balance", "account_index": 3}
```

반환:
```json
{"address": "0x...", "balance_wei": "10000000000000000000000", "balance_eth": "10000"}
```

### call

컨트랙트 읽기 함수 호출 (view/pure). 가스 불필요.

```json
{
  "action": "call",
  "contract": "0x...",
  "abi_name": "erc20",
  "function": "balanceOf",
  "args": ["0x..."]
}
```

### transact

컨트랙트 쓰기 함수 호출. 서명 필요.

```json
// 기본 계정으로 전송
{
  "action": "transact",
  "contract": "0x...",
  "abi_name": "erc20",
  "function": "transfer",
  "args": ["0xRecipient...", "1000000000000000000"],
  "value": "0"
}

// account #5로 전송
{
  "action": "transact",
  "contract": "0x...",
  "abi_name": "erc20",
  "function": "transfer",
  "args": ["0xRecipient...", "1000000000000000000"],
  "account_index": 5
}
```

반환:
```json
{"tx_hash": "0x...", "status": "success", "from": "0x...", "block_number": 5, "gas_used": 52000}
```

### send_eth

ETH 단순 전송. 서명 필요.

수신자 지정 방법 2가지:
- `address` — 외부 주소로 전송 (임의의 이더리움 주소)
- `to_account_index` — 같은 시드의 HD wallet 계정 인덱스로 전송 (주소를 자동 파생)

둘 중 하나만 지정하면 된다. `to_account_index`를 사용하면 LLM이 주소를 알 필요 없이 인덱스만으로 전송 가능.

```json
// 외부 주소로 전송
{"action": "send_eth", "address": "0xRecipient...", "value": "1.5"}

// account #3에서 외부 주소로 전송
{"action": "send_eth", "address": "0xRecipient...", "value": "1.5", "account_index": 3}

// account #0에서 account #20으로 전송 (주소 자동 파생)
{"action": "send_eth", "to_account_index": 20, "value": "50"}

// account #3에서 account #7로 전송
{"action": "send_eth", "to_account_index": 7, "value": "0.1", "account_index": 3}
```

`value`는 ETH 단위 (wei 아님).

### get_tx

트랜잭션 상세 조회.

```json
{"action": "get_tx", "tx_hash": "0x..."}
```

반환:
```json
{
  "hash": "0x...",
  "from": "0x...",
  "to": "0x...",
  "value_eth": "1.5",
  "gas": 21000,
  "gas_price_gwei": "1.875",
  "nonce": 0,
  "block_number": 1,
  "status": "success"
}
```

### get_block

블록 정보 조회. `block` 생략 시 "latest".

```json
{"action": "get_block", "block": "latest"}
```

반환:
```json
{
  "number": 1,
  "hash": "0x...",
  "timestamp": 1770671069,
  "transactions": 1,
  "gas_used": 21000,
  "gas_limit": 60000000
}
```

### list_contracts

등록된 컨트랙트 목록 조회.

```json
{"action": "list_contracts"}
```

반환:
```json
{
  "contracts": {
    "TTK": {"address": "0xa513...", "abi": "erc20", "description": "testToken (TTK), 18 decimals"},
    "USDC": {"address": "0x...", "abi": "erc20", "description": "USD Coin, 6 decimals"}
  }
}
```

### register_contract

새 컨트랙트를 레지스트리에 등록. 등록 후 `contract` 파라미터에 이름으로 사용 가능.

```json
{
  "action": "register_contract",
  "contract_name": "TTK",
  "contract": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
  "abi_name": "erc20",
  "contract_description": "testToken (TTK), 18 decimals"
}
```

등록 후 이름으로 호출:
```json
{"action": "call", "contract": "TTK", "function": "balanceOf", "args": ["0x..."]}
{"action": "transact", "contract": "TTK", "function": "transfer", "to_account_index": 20, "args": ["1000000000000000000"]}
```

## 컨트랙트 레지스트리

### 개요

컨트랙트 이름 → 주소 + ABI 매핑을 관리한다. 등록하면 `contract` 파라미터에 주소 대신 이름을 사용할 수 있다.

- 파일 위치: `~/.nanobot/workspace/ethereum/contracts.json`
- Tool 시작 시 자동 로드
- `register_contract` action으로 런타임 등록 가능
- `abi_name`은 자동 해석 (레지스트리에 등록된 ABI 사용)

### 등록 방법

#### 1. 텔레그램/CLI에서 LLM에게 요청

```
TTK 토큰 등록해줘. 주소는 0xa513..., abi는 erc20, 18 decimals
```

LLM이 `register_contract` action을 호출하여 등록한다.

#### 2. 직접 파일 편집

```json
// ~/.nanobot/workspace/ethereum/contracts.json
{
  "TTK": {
    "address": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
    "abi": "erc20",
    "description": "testToken (TTK), 18 decimals"
  },
  "MyDEX": {
    "address": "0x...",
    "abi": "mydex",
    "description": "Custom DEX router"
  }
}
```

파일 편집 후 게이트웨이 재시작 필요.

### 커스텀 ABI 컨트랙트 등록

표준 ERC20/ERC721이 아닌 컨트랙트는 ABI 파일을 먼저 추가한 후 등록:

```bash
# 1. ABI 파일 추가
cp MyDEX.json ~/.nanobot/workspace/ethereum/abis/mydex.json

# 2. 레지스트리에 등록 (파일 편집 또는 register_contract)
```

## ABI 관리

### 기본 ABI

Tool 초기화 시 다음 파일이 자동 생성된다:

```
~/.nanobot/workspace/ethereum/abis/
  erc20.json    — ERC20 표준 (transfer, approve, balanceOf 등)
  erc721.json   — ERC721 표준 (ownerOf, safeTransferFrom 등)
```

### 새 컨트랙트 추가

코드 수정 없이 ABI 파일만 추가하면 된다:

```bash
# 1. ABI 파일 복사
cp MyContract.json ~/.nanobot/workspace/ethereum/abis/mycontract.json
```

이후 LLM이 `abi_name: "mycontract"`로 호출 가능:

```json
{
  "action": "call",
  "contract": "0xDeployedAddress...",
  "abi_name": "mycontract",
  "function": "myFunction",
  "args": [42]
}
```

Hardhat/Foundry artifact 포맷(`{"abi": [...]}`)도 자동 인식한다.

### ABI 파일 포맷

표준 JSON ABI 배열:

```json
[
  {
    "inputs": [{"name": "account", "type": "address"}],
    "name": "balanceOf",
    "outputs": [{"name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  }
]
```

## 보안

| 항목 | 설명 |
|------|------|
| 키 격리 | LLM은 개인키/seed에 접근 불가. Tool 반환값에 키 미포함 |
| Seed 암호화 | Fernet + PBKDF2 (패스워드 기반) |
| 읽기/쓰기 분리 | seed 없으면 자동으로 읽기 전용 모드 |
| 가스 한도 | config `gasLimit`으로 최대 가스 제한 |
| 주소 검증 | checksum 주소 유효성 검사 |
| 로그 안전 | 로그에 키/seed/서명 데이터 미포함 |
| 메모리 관리 | seed/private key는 `_account` 내부에만 보관, 직렬화 불가 |

## 네트워크 참조

| 네트워크 | RPC URL | Chain ID |
|----------|---------|----------|
| Hardhat/Anvil (로컬) | `http://127.0.0.1:8545` | 31337 |
| Sepolia (테스트넷) | `https://rpc.sepolia.org` | 11155111 |
| Ethereum Mainnet | `https://eth.llamarpc.com` | 1 |

## 사용 예시

### CLI에서 직접 대화

```bash
# Hardhat 로컬 노드 실행
npx hardhat node

# 다른 터미널에서
ETH_MNEMONIC="test test test test test test test test test test test junk" \
  nanobot agent -m "내 이더리움 잔액 확인해줘"
# → 10,000 ETH

ETH_MNEMONIC="test test test test test test test test test test test junk" \
  nanobot agent -m "0x70997970C51812dc3A010C7d01b50e0d17dc79C8에 0.5 ETH 보내줘"
# → 송금 성공, tx hash 반환
```

### Telegram 봇에서

```bash
# 게이트웨이 실행
ETH_MNEMONIC="test test test..." nanobot gateway
```

Telegram에서 봇에게:
- "내 이더리움 잔액 알려줘"
- "0x... 주소로 1 ETH 보내줘"
- "최신 블록 정보 확인해줘"

### 다중 계정 활용

하나의 seed에서 `account_index`로 여러 계정을 런타임에 전환할 수 있다:

```
"account 0~4번의 잔액을 각각 확인해줘"
```

LLM이 호출:
```json
{"action": "get_balance", "account_index": 0}
{"action": "get_balance", "account_index": 1}
{"action": "get_balance", "account_index": 2}
{"action": "get_balance", "account_index": 3}
{"action": "get_balance", "account_index": 4}
```

계정 간 전송 (`to_account_index` 사용 — 주소 조회 불필요):
```
"account 3에서 account 7로 0.1 ETH 보내줘"
```

LLM이 호출:
```json
{"action": "send_eth", "to_account_index": 7, "value": "0.1", "account_index": 3}
```

외부 주소로 전송:
```
"account 0에서 0x1234...에 1 ETH 보내줘"
```

LLM이 호출:
```json
{"action": "send_eth", "address": "0x1234...", "value": "1", "account_index": 0}
```

### 토큰 잔액 조회

```
"0xTokenContract의 erc20 balanceOf를 내 주소로 조회해줘"
```

LLM이 호출:
```json
{
  "action": "call",
  "contract": "0xTokenContract...",
  "abi_name": "erc20",
  "function": "balanceOf",
  "args": ["0xMyAddress..."]
}
```

## 트러블슈팅

### "Web3 not connected" 에러
- RPC URL이 맞는지 확인: `curl http://127.0.0.1:8545`
- Hardhat/Anvil 노드가 실행 중인지 확인

### "No account configured" 에러
- `ETH_MNEMONIC` 또는 `ETH_SEED_PASSWORD` 환경변수 확인
- `nanobot ethereum status`로 계정 상태 확인

### Tool이 등록되지 않음
- `config.json`에서 `tools.ethereum.enabled`가 `true`인지 확인
- `web3` 패키지 설치 확인: `pip install web3`
- 게이트웨이 실행 중이었다면 **재시작 필요**

### ABI 파일을 찾을 수 없음
- `~/.nanobot/workspace/ethereum/abis/` 디렉토리 확인
- 파일명이 `abi_name` + `.json`과 일치하는지 확인

### Hardhat 기본 계정 주소 참조

HD Wallet 파생 경로 섹션의 계정 테이블 참조. 각 계정의 초기 잔액: 10,000 ETH.

Seed: `test test test test test test test test test test test junk`
