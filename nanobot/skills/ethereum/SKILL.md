---
name: ethereum
description: Interact with Ethereum blockchain. Use when the user asks about ETH balances, token balances, sending ETH, contract calls, transactions, or blocks. Covers ERC20/ERC721 tokens, multi-account HD wallet operations, contract registry, and smart contract interactions.
---

# Ethereum

Use the `ethereum` tool for all blockchain operations.

## Quick Reference

| Action | Use case | Key params |
|--------|----------|------------|
| `get_balance` | ETH balance | `account_index` or `address` |
| `send_eth` | Transfer ETH | `address` or `to_account_index`, `value`, `account_index` |
| `call` | Read contract (view) | `contract`, `function`, `args` |
| `transact` | Write contract | `contract`, `function`, `args`, `account_index` |
| `get_tx` | Transaction details | `tx_hash` |
| `get_block` | Block info | `block` |
| `list_contracts` | Show registered contracts | — |
| `register_contract` | Register new contract | `contract_name`, `contract`, `abi_name` |

## Contract Registry

Contracts can be registered by name. Use names instead of 0x addresses:

```json
{"action": "list_contracts"}
{"action": "call", "contract": "TTK", "function": "balanceOf", "args": ["0xHolder..."]}
{"action": "transact", "contract": "TTK", "function": "transfer", "to_account_index": 20, "args": ["1000000000000000000"]}
```

When a registered name is used, `abi_name` is auto-resolved from the registry. No need to specify it.

Register a new contract:
```json
{"action": "register_contract", "contract_name": "USDC", "contract": "0x...", "abi_name": "erc20", "contract_description": "USD Coin, 6 decimals"}
```

## Multi-Account (HD Wallet)

All accounts derive from the same seed. Use index to switch:

- `account_index` — sender account
- `to_account_index` — recipient account (send_eth, transact). Resolves address automatically.

Account-to-account ETH transfer:
```json
{"action": "send_eth", "to_account_index": 7, "value": "1.0", "account_index": 3}
```

Account-to-account token transfer:
```json
{"action": "transact", "contract": "TTK", "function": "transfer", "to_account_index": 20, "args": ["1000000000000000000"], "account_index": 0}
```

When `to_account_index` is provided for transact, the tool derives the recipient address and injects it into the correct arg position. Only provide non-address args (e.g. amount).

## ERC20 Token Operations

### Check token balance
```json
{"action": "call", "contract": "TTK", "function": "balanceOf", "args": ["0xHolderAddress"]}
```

Result is in raw units. Divide by `10^decimals`:
```json
{"action": "call", "contract": "TTK", "function": "decimals"}
```

### Token info
```json
{"action": "call", "contract": "TTK", "function": "symbol"}
{"action": "call", "contract": "TTK", "function": "name"}
{"action": "call", "contract": "TTK", "function": "totalSupply"}
```

### Transfer tokens
```json
{"action": "transact", "contract": "TTK", "function": "transfer", "to_account_index": 20, "args": ["1000000000000000000"]}
```

Amount must be in raw units (wei-equivalent). For 1 token with 18 decimals: `"1000000000000000000"`.

### Approve + transferFrom pattern
```json
{"action": "transact", "contract": "TTK", "function": "approve", "args": ["0xSpender", "1000000000000000000"]}
{"action": "call", "contract": "TTK", "function": "allowance", "args": ["0xOwner", "0xSpender"]}
```

## ERC721 (NFT) Operations

```json
{"action": "call", "contract": "0xNFT", "abi_name": "erc721", "function": "ownerOf", "args": [1]}
{"action": "call", "contract": "0xNFT", "abi_name": "erc721", "function": "balanceOf", "args": ["0xOwner"]}
{"action": "call", "contract": "0xNFT", "abi_name": "erc721", "function": "tokenURI", "args": [1]}
```

## Common Patterns

**Multiple balance check** — call `get_balance` for each account_index sequentially.

**Token balance with symbol** — first get `symbol` and `decimals`, then `balanceOf`, format result as `{amount} {symbol}`.

**Verify transfer** — after `send_eth` or `transact`, call `get_balance` or `balanceOf` to confirm.
