"""Ethereum tool for blockchain interactions."""

import base64
import json
import os
from pathlib import Path
from typing import Any

from loguru import logger

from nanobot.agent.tools.base import Tool


# Default ABIs bundled with the tool
ERC20_ABI = [
    {"inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "transferFrom", "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"anonymous": False, "inputs": [{"indexed": True, "name": "from", "type": "address"}, {"indexed": True, "name": "to", "type": "address"}, {"indexed": False, "name": "value", "type": "uint256"}], "name": "Transfer", "type": "event"},
    {"anonymous": False, "inputs": [{"indexed": True, "name": "owner", "type": "address"}, {"indexed": True, "name": "spender", "type": "address"}, {"indexed": False, "name": "value", "type": "uint256"}], "name": "Approval", "type": "event"},
]

ERC721_ABI = [
    {"inputs": [{"name": "owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "ownerOf", "outputs": [{"name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI", "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "name": "approve", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "getApproved", "outputs": [{"name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "operator", "type": "address"}, {"name": "approved", "type": "bool"}], "name": "setApprovalForAll", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "owner", "type": "address"}, {"name": "operator", "type": "address"}], "name": "isApprovedForAll", "outputs": [{"name": "", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "name": "transferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "tokenId", "type": "uint256"}, {"name": "data", "type": "bytes"}], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
]


def _derive_account(mnemonic: str, index: int = 0):
    """Derive an Ethereum account from a mnemonic using BIP-44 path."""
    from eth_account import Account
    Account.enable_unaudited_hdwallet_features()
    path = f"m/44'/60'/0'/0/{index}"
    return Account.from_mnemonic(mnemonic, account_path=path)


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2."""
    import hashlib
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=480000, dklen=32)
    return base64.urlsafe_b64encode(dk)


def encrypt_seed(mnemonic: str, password: str, path: Path) -> str:
    """Encrypt and save seed phrase. Returns derived address."""
    from cryptography.fernet import Fernet

    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(mnemonic.encode())

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "salt": base64.b64encode(salt).decode(),
        "data": encrypted.decode(),
    }
    path.write_text(json.dumps(payload))

    acct = _derive_account(mnemonic, 0)
    return acct.address


def decrypt_seed(password: str, path: Path) -> str:
    """Decrypt seed phrase from file."""
    from cryptography.fernet import Fernet

    payload = json.loads(path.read_text())
    salt = base64.b64decode(payload["salt"])
    key = _derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(payload["data"].encode()).decode()


class EthereumTool(Tool):
    """Tool for Ethereum blockchain interactions."""

    def __init__(self, config):
        from nanobot.config.schema import EthereumConfig
        self._config: EthereumConfig = config
        self._w3 = None
        self._account = None
        self._mnemonic: str | None = None  # kept in memory for multi-account derivation
        self._abis_dir = Path(config.abis_dir).expanduser()
        self._contracts_file = self._abis_dir.parent / "contracts.json"
        self._contracts: dict[str, dict] = {}
        self._init_web3()
        self._init_account()
        self._ensure_default_abis()
        self._load_contracts()

    def _init_web3(self) -> None:
        """Initialize Web3 connection."""
        try:
            from web3 import Web3
            self._w3 = Web3(Web3.HTTPProvider(self._config.rpc_url))
            logger.info(f"Ethereum: connected to {self._config.rpc_url}")
        except Exception as e:
            logger.warning(f"Ethereum: failed to connect to {self._config.rpc_url}: {e}")

    def _init_account(self) -> None:
        """Load account from env var or encrypted file."""
        # Priority 1: environment variable
        mnemonic = os.environ.get("ETH_MNEMONIC")
        if mnemonic:
            mnemonic = mnemonic.strip()
            try:
                self._mnemonic = mnemonic
                self._account = _derive_account(mnemonic, self._config.account_index)
                logger.info(f"Ethereum: account loaded from ETH_MNEMONIC ({self._account.address})")
                return
            except Exception as e:
                logger.warning(f"Ethereum: failed to derive from ETH_MNEMONIC: {e}")

        # Priority 2: encrypted seed file (needs ETH_SEED_PASSWORD env)
        seed_path = Path(self._config.seed_file).expanduser()
        password = os.environ.get("ETH_SEED_PASSWORD")
        if seed_path.exists() and password:
            try:
                mnemonic = decrypt_seed(password, seed_path)
                self._mnemonic = mnemonic
                self._account = _derive_account(mnemonic, self._config.account_index)
                logger.info(f"Ethereum: account loaded from {seed_path} ({self._account.address})")
                return
            except Exception as e:
                logger.warning(f"Ethereum: failed to decrypt seed: {e}")

        # No account = read-only mode
        logger.info("Ethereum: no account configured, read-only mode")

    def _ensure_default_abis(self) -> None:
        """Create default ABI files if they don't exist."""
        self._abis_dir.mkdir(parents=True, exist_ok=True)
        defaults = {"erc20": ERC20_ABI, "erc721": ERC721_ABI}
        for name, abi in defaults.items():
            path = self._abis_dir / f"{name}.json"
            if not path.exists():
                path.write_text(json.dumps(abi, indent=2))
                logger.info(f"Ethereum: created default ABI {path}")

    def _load_contracts(self) -> None:
        """Load contract registry from contracts.json."""
        if self._contracts_file.exists():
            try:
                self._contracts = json.loads(self._contracts_file.read_text())
                logger.info(f"Ethereum: loaded {len(self._contracts)} contracts from registry")
            except Exception as e:
                logger.warning(f"Ethereum: failed to load contracts.json: {e}")

    def _save_contracts(self) -> None:
        """Save contract registry to contracts.json."""
        self._contracts_file.parent.mkdir(parents=True, exist_ok=True)
        self._contracts_file.write_text(json.dumps(self._contracts, indent=2))

    def _resolve_contract(self, contract: str | None) -> tuple[str, str | None]:
        """Resolve contract name or address. Returns (address, abi_name or None)."""
        from web3 import Web3
        if not contract:
            raise ValueError("contract is required")
        # If it's a valid address, return as-is
        if Web3.is_address(contract):
            return Web3.to_checksum_address(contract), None
        # Look up in registry (case-insensitive)
        key = contract.upper()
        for name, info in self._contracts.items():
            if name.upper() == key:
                addr = Web3.to_checksum_address(info["address"])
                return addr, info.get("abi")
        raise ValueError(f"Contract '{contract}' not found in registry. Use list_contracts to see available contracts, or provide a 0x address.")

    def _get_account(self, account_index: int | None = None):
        """Get account for the given index, or default account."""
        if account_index is not None and self._mnemonic:
            return _derive_account(self._mnemonic, account_index)
        if account_index is not None and not self._mnemonic:
            raise ValueError("No seed available. Cannot derive account for custom index.")
        if self._account:
            return self._account
        raise ValueError("No account configured. Set ETH_MNEMONIC or run 'nanobot ethereum init'.")

    def validate_params(self, params: dict[str, Any]) -> list[str]:
        """Override to coerce params that LLMs often send as wrong types."""
        for key in ("account_index", "to_account_index"):
            if key in params:
                try:
                    params[key] = int(params[key])
                except (ValueError, TypeError):
                    return [f"{key} must be an integer"]
        # LLMs often send args as JSON string instead of array
        if "args" in params and isinstance(params["args"], str):
            try:
                params["args"] = json.loads(params["args"])
            except (json.JSONDecodeError, TypeError):
                return ["args must be a JSON array"]
        return super().validate_params(params)

    def _load_abi(self, abi_name: str) -> list[dict]:
        """Load ABI from file."""
        path = self._abis_dir / f"{abi_name}.json"
        if not path.exists():
            raise FileNotFoundError(f"ABI file not found: {path}")
        data = json.loads(path.read_text())
        # Handle Hardhat/Foundry artifact format: { "abi": [...] }
        if isinstance(data, dict) and "abi" in data:
            return data["abi"]
        return data

    @property
    def name(self) -> str:
        return "ethereum"

    @property
    def description(self) -> str:
        addr = self._account.address if self._account else "read-only (no key)"
        mode = "read/write" if self._account else "read-only"
        contracts_hint = ""
        if self._contracts:
            names = ", ".join(self._contracts.keys())
            contracts_hint = f" Registered contracts: {names}."
        return (
            f"Interact with Ethereum blockchain ({mode}). "
            f"Account: {addr}. "
            f"Chain ID: {self._config.chain_id}, RPC: {self._config.rpc_url}. "
            "Actions: get_balance, call, transact, send_eth, get_tx, get_block, list_contracts, register_contract. "
            "For call/transact: 'contract' can be a registered name (e.g. 'TTK') or 0x address. "
            "Use 'to_account_index' for recipient by HD wallet index (send_eth, transact). "
            "Use 'account_index' to change the sender."
            f"{contracts_hint}"
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["get_balance", "call", "transact", "send_eth", "get_tx", "get_block", "list_contracts", "register_contract"],
                    "description": "Action to perform",
                },
                "address": {
                    "type": "string",
                    "description": "Target address (for get_balance, send_eth)",
                },
                "contract": {
                    "type": "string",
                    "description": "Contract address OR registered name (for call, transact, register_contract). Names are resolved from contracts registry.",
                },
                "abi_name": {
                    "type": "string",
                    "description": "ABI filename without .json (e.g. 'erc20'). Auto-resolved if contract is a registered name.",
                },
                "contract_name": {
                    "type": "string",
                    "description": "Name to register (for register_contract). e.g. 'TTK', 'USDC'",
                },
                "contract_description": {
                    "type": "string",
                    "description": "Description for register_contract. e.g. 'testToken, 18 decimals'",
                },
                "function": {
                    "type": "string",
                    "description": "Contract function name (for call, transact)",
                },
                "args": {
                    "type": "array",
                    "description": "Function arguments",
                },
                "value": {
                    "type": "string",
                    "description": "ETH amount in ether (for send_eth, transact with payable)",
                },
                "tx_hash": {
                    "type": "string",
                    "description": "Transaction hash (for get_tx)",
                },
                "block": {
                    "type": "string",
                    "description": "Block number or 'latest' (for get_block)",
                },
                "account_index": {
                    "type": "integer",
                    "description": "HD wallet account index to use as sender instead of default (derives from same seed)",
                },
                "to_account_index": {
                    "type": "integer",
                    "description": "HD wallet account index for recipient (for send_eth, transact). Derives recipient address from same seed. For transact, auto-injects address into the correct arg position.",
                },
            },
            "required": ["action"],
        }

    async def execute(
        self,
        action: str,
        address: str | None = None,
        contract: str | None = None,
        abi_name: str | None = None,
        function: str | None = None,
        args: list | None = None,
        value: str | None = None,
        tx_hash: str | None = None,
        block: str | None = None,
        account_index: int | None = None,
        to_account_index: int | None = None,
        contract_name: str | None = None,
        contract_description: str | None = None,
        **kwargs: Any,
    ) -> str:
        # list_contracts and register_contract don't need web3
        if action == "list_contracts":
            return self._list_contracts()
        if action == "register_contract":
            return self._register_contract(contract_name, contract, abi_name, contract_description)

        if not self._w3:
            return "Error: Web3 not connected. Check RPC URL."

        # Coerce index params to int (LLMs sometimes send them as string)
        if account_index is not None:
            account_index = int(account_index)
        if to_account_index is not None:
            to_account_index = int(to_account_index)

        # Resolve contract name → address + abi_name
        if contract and action in ("call", "transact"):
            resolved_addr, resolved_abi = self._resolve_contract(contract)
            contract = resolved_addr
            if resolved_abi and not abi_name:
                abi_name = resolved_abi

        try:
            if action == "get_balance":
                return self._get_balance(address, account_index)
            elif action == "call":
                return self._call(contract, abi_name, function, args)
            elif action == "transact":
                return self._transact(contract, abi_name, function, args, value, account_index, to_account_index)
            elif action == "send_eth":
                return self._send_eth(address, value, account_index, to_account_index)
            elif action == "get_tx":
                return self._get_tx(tx_hash)
            elif action == "get_block":
                return self._get_block(block)
            else:
                return f"Error: unknown action '{action}'"
        except Exception as e:
            return f"Error: {e}"

    def _validate_address(self, addr: str | None, label: str = "address") -> str:
        """Validate and return checksummed address."""
        from web3 import Web3
        if not addr:
            raise ValueError(f"{label} is required")
        if not Web3.is_address(addr):
            raise ValueError(f"Invalid {label}: {addr}")
        return Web3.to_checksum_address(addr)

    def _get_balance(self, address: str | None, account_index: int | None = None) -> str:
        from web3 import Web3
        # Resolve address: explicit > account_index > default account
        if not address:
            if account_index is not None:
                acct = self._get_account(account_index)
                address = acct.address
            elif self._account:
                address = self._account.address
        addr = self._validate_address(address)
        balance_wei = self._w3.eth.get_balance(addr)
        balance_eth = Web3.from_wei(balance_wei, "ether")
        return json.dumps({
            "address": addr,
            "balance_wei": str(balance_wei),
            "balance_eth": str(balance_eth),
        })

    def _call(self, contract: str | None, abi_name: str | None, function: str | None, args: list | None) -> str:
        from web3 import Web3
        addr = self._validate_address(contract, "contract")
        if not abi_name:
            raise ValueError("abi_name is required for call")
        if not function:
            raise ValueError("function is required for call")

        abi = self._load_abi(abi_name)
        contract_obj = self._w3.eth.contract(address=addr, abi=abi)
        fn = contract_obj.functions[function]
        result = fn(*(args or [])).call()

        # Convert bytes/HexBytes to hex string for JSON serialization
        result = self._serialize_result(result)
        return json.dumps({"result": result})

    def _get_fee_params(self) -> dict:
        """Get gas fee parameters. Uses EIP-1559 if supported, falls back to legacy."""
        try:
            latest = self._w3.eth.get_block("latest")
            base_fee = latest.get("baseFeePerGas")
        except Exception:
            base_fee = None

        if base_fee is not None:
            # EIP-1559 (Type 2)
            max_priority_fee = self._w3.eth.max_priority_fee
            return {
                "maxPriorityFeePerGas": max_priority_fee,
                "maxFeePerGas": (2 * base_fee) + max_priority_fee,
            }
        else:
            # Legacy (pre-London)
            return {"gasPrice": self._w3.eth.gas_price}

    def _inject_to_address(self, abi: list[dict], function: str, args: list, to_address: str) -> list:
        """Inject resolved to_address into args at the correct position based on ABI."""
        # Find function definition in ABI
        func_inputs = None
        for item in abi:
            if item.get("type") == "function" and item.get("name") == function:
                func_inputs = item.get("inputs", [])
                break
        if not func_inputs:
            return [to_address] + args  # fallback: prepend

        # Priority 1: address param named "to", "_to", "recipient", "dst"
        to_names = {"to", "_to", "recipient", "dst", "destination"}
        target_idx = None
        for i, inp in enumerate(func_inputs):
            if inp["type"] == "address" and inp["name"].lower() in to_names:
                target_idx = i
                break
        # Priority 2: first address param
        if target_idx is None:
            for i, inp in enumerate(func_inputs):
                if inp["type"] == "address":
                    target_idx = i
                    break

        if target_idx is None:
            return args  # no address param found

        # Replace or insert at target position
        if target_idx < len(args):
            args[target_idx] = to_address
        else:
            while len(args) < target_idx:
                args.append(None)
            args.insert(target_idx, to_address)
        return args

    def _transact(self, contract: str | None, abi_name: str | None, function: str | None, args: list | None, value: str | None, account_index: int | None = None, to_account_index: int | None = None) -> str:
        from web3 import Web3
        acct = self._get_account(account_index)

        addr = self._validate_address(contract, "contract")
        if not abi_name:
            raise ValueError("abi_name is required for transact")
        if not function:
            raise ValueError("function is required for transact")

        abi = self._load_abi(abi_name)

        # Resolve to_account_index → inject address into args
        args = list(args or [])
        if to_account_index is not None:
            to_addr = self._get_account(to_account_index).address
            args = self._inject_to_address(abi, function, args, to_addr)

        contract_obj = self._w3.eth.contract(address=addr, abi=abi)
        fn = contract_obj.functions[function]

        tx_params = {
            "from": acct.address,
            "nonce": self._w3.eth.get_transaction_count(acct.address),
            "gas": self._config.gas_limit,
            "chainId": self._config.chain_id,
            **self._get_fee_params(),
        }

        if value:
            tx_params["value"] = Web3.to_wei(value, "ether")

        # Build, sign, and send transaction
        tx = fn(*args).build_transaction(tx_params)
        signed = acct.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return json.dumps({
            "tx_hash": receipt.transactionHash.hex(),
            "status": "success" if receipt.status == 1 else "failed",
            "from": acct.address,
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        })

    def _send_eth(self, address: str | None, value: str | None, account_index: int | None = None, to_account_index: int | None = None) -> str:
        from web3 import Web3
        acct = self._get_account(account_index)
        if not value:
            raise ValueError("value (ETH amount) is required for send_eth")

        # Resolve recipient: to_account_index > address
        if to_account_index is not None:
            to_acct = self._get_account(to_account_index)
            to_addr = to_acct.address
        else:
            to_addr = self._validate_address(address)

        tx = {
            "to": to_addr,
            "from": acct.address,
            "value": Web3.to_wei(value, "ether"),
            "nonce": self._w3.eth.get_transaction_count(acct.address),
            "gas": 21000,
            "chainId": self._config.chain_id,
            **self._get_fee_params(),
        }

        signed = acct.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return json.dumps({
            "tx_hash": receipt.transactionHash.hex(),
            "status": "success" if receipt.status == 1 else "failed",
            "from": acct.address,
            "to": to_addr,
            "value_eth": value,
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        })

    def _get_tx(self, tx_hash: str | None) -> str:
        from web3 import Web3
        if not tx_hash:
            raise ValueError("tx_hash is required for get_tx")

        tx = self._w3.eth.get_transaction(tx_hash)
        receipt = None
        try:
            receipt = self._w3.eth.get_transaction_receipt(tx_hash)
        except Exception:
            pass

        result = {
            "hash": tx.hash.hex(),
            "from": tx["from"],
            "to": tx.to,
            "value_eth": str(Web3.from_wei(tx.value, "ether")),
            "gas": tx.gas,
            "gas_price_gwei": str(Web3.from_wei(tx.gasPrice, "gwei")) if tx.gasPrice else None,
            "nonce": tx.nonce,
            "block_number": tx.blockNumber,
            "input": tx.input.hex() if tx.input else "0x",
        }
        if receipt:
            result["status"] = "success" if receipt.status == 1 else "failed"
            result["gas_used"] = receipt.gasUsed

        return json.dumps(result)

    def _get_block(self, block: str | None) -> str:
        block_id = "latest"
        if block is not None:
            block_id = int(block) if block.isdigit() else block

        blk = self._w3.eth.get_block(block_id)
        return json.dumps({
            "number": blk.number,
            "hash": blk.hash.hex(),
            "timestamp": blk.timestamp,
            "transactions": len(blk.transactions),
            "gas_used": blk.gasUsed,
            "gas_limit": blk.gasLimit,
            "miner": blk.miner if hasattr(blk, "miner") else None,
        })

    def _list_contracts(self) -> str:
        """List all registered contracts."""
        if not self._contracts:
            return json.dumps({"contracts": {}, "message": "No contracts registered. Use register_contract to add one."})
        return json.dumps({"contracts": self._contracts})

    def _register_contract(self, name: str | None, address: str | None, abi_name: str | None, description: str | None = None) -> str:
        """Register a contract in the registry."""
        from web3 import Web3
        if not name:
            raise ValueError("contract_name is required")
        if not address or not Web3.is_address(address):
            raise ValueError("contract (valid 0x address) is required")
        addr = Web3.to_checksum_address(address)
        entry = {"address": addr}
        if abi_name:
            entry["abi"] = abi_name
        if description:
            entry["description"] = description
        self._contracts[name] = entry
        self._save_contracts()
        return json.dumps({"registered": name, **entry})

    def _serialize_result(self, value: Any) -> Any:
        """Convert Web3 types to JSON-serializable values."""
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if isinstance(value, (list, tuple)):
            return [self._serialize_result(v) for v in value]
        if isinstance(value, dict):
            return {k: self._serialize_result(v) for k, v in value.items()}
        if isinstance(value, int) and abs(value) > 2**53:
            return str(value)
        return value
