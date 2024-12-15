import datetime as dt
import hashlib
from logging import INFO as LOG_INFO_LEVEL
from logging import Logger
from typing import Optional, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

logger = Logger(__name__)
logger.setLevel(LOG_INFO_LEVEL)


class Wallet:
    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()
        self.address = hashlib.sha256(self.public_key.encode()).hexdigest()

    def get_public_key(self) -> str:
        """
        Return the (serialized) public key of this wallet.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @property
    def public_key(self) -> str:
        return self.get_public_key()

    def sign(self, data: bytes) -> str:
        """
        Sign data using the private key of this wallet.
        """
        signature = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        return f"{r}:{s}"

    @staticmethod
    def verify(public_key_pem: str, data: bytes, signature: str) -> bool:
        """
        Verify signature using the provided public key
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            r_str, s_str = signature.split(":")
            r, s = int(r_str), int(s_str)

            signature_bytes = encode_dss_signature(r, s)
            public_key.verify(signature_bytes, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logger.info("Invalid Signature.")
            return False
        except Exception as e:
            logger.warning(f"Verification error: {e}")
            return False


class Transaction:
    def __init__(self, sender_address: str, receiver_address: str, amount: int):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.amount = amount
        self.signature = None
        self.public_key = None

    def __repr__(self):
        return (
            f"Transaction({self.sender_address},{self.receiver_address},{self.amount})"
        )

    def __str__(self):
        return self.__repr__()

    def to_dict(self) -> dict[str, any]:
        if self.public_key is None:
            public_key = None
        else:
            public_key = (
                self.public_key.removeprefix("-----BEGIN PUBLIC KEY-----\n")
                .removesuffix("\n-----END PUBLIC KEY-----\n")
                .strip()
            )
        return {
            "sender_address": self.sender_address,
            "receiver_address": self.receiver_address,
            "amount": self.amount,
            "signature": self.signature,
            "public_key": public_key,
        }

    @staticmethod
    def from_dict(data: dict) -> "Transaction":
        tsx = Transaction(
            sender_address=data["sender_address"],
            receiver_address=data["receiver_address"],
            amount=data["amount"],
        )
        tsx.signature = data["signature"]
        if data["public_key"] is not None:
            tsx.public_key = (
                "-----BEGIN PUBLIC KEY-----\n"
                + data["public_key"]
                + "\n-----END PUBLIC KEY-----\n"
            )
        return tsx

    def to_hashable(self) -> str:
        return f"{self.sender_address}{self.receiver_address}{self.amount}"

    def to_hashable_bytes(self) -> bytes:
        return self.to_hashable().encode()

    def sign(self, sender_wallet: Wallet) -> bool:
        """
        Sign the transaction using the senders wallet.

        Returns true is signing was successful.
        """
        if sender_wallet.address != self.sender_address:
            logger.warning("Trying to sign with non-sender wallet!")
            return False
        self.signature = sender_wallet.sign(self.to_hashable_bytes())
        self.public_key = sender_wallet.public_key

        return True

    def is_signed(self) -> bool:
        return (self.signature is not None) and (self.public_key is not None)

    def verify(self) -> bool:
        if not self.is_signed:
            logger.warning("Trying to verify unsigned transaction.")
            return False
        return Wallet.verify(
            public_key_pem=self.public_key,
            data=self.to_hashable_bytes(),
            signature=self.signature,
        )


def compute_merkle_root(transactions: list[Transaction]) -> str:
    """Compute the Merkle root from a list of transactions."""
    if not transactions:
        return hashlib.sha256(b"").hexdigest()

    hashes = [
        hashlib.sha256(tsx.to_hashable_bytes()).hexdigest() for tsx in transactions
    ]

    while len(hashes) > 1:
        temp_hashes = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                combined = hashes[i] + hashes[i + 1]
            else:  # Duplicate on: last hash and no pair
                combined = hashes[i] + hashes[i]
            temp_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
        hashes = temp_hashes

    return hashes[0]


class Block:
    def __init__(
        self,
        index: int,
        timestamp: dt.datetime,
        transactions: list[Transaction],
        previous_hash: str,
        nonce: int,
    ):
        self.index = index
        self.timestamp = timestamp
        self._transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = self.compute_merkle_root()

    def __repr__(self):
        return (
            f"Block(index={self.index}, timestamp={self.timestamp!r}, "
            f"transactions={self._transactions}, previous_hash={self.previous_hash!r}, nonce={self.nonce})"
        )

    def __str__(self):
        return self.__repr__()

    def get_transactions(self) -> list[Transaction]:
        return self._transactions.copy()

    def to_dict(self) -> dict[str, str]:
        return {
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "transactions": [tsx.to_dict() for tsx in self._transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }

    @staticmethod
    def from_dict(data: dict) -> "Block":
        tsxs = [Transaction.from_dict(tsx_data) for tsx_data in data["transactions"]]
        return Block(
            index=data["index"],
            timestamp=dt.datetime.fromisoformat(data["timestamp"]),
            transactions=tsxs,
            previous_hash=data["previous_hash"],
            nonce=data["nonce"],
        )

    def compute_merkle_root(self) -> str:
        return compute_merkle_root(self._transactions)

    def get_hash(self) -> str:
        encryption = hashlib.sha256()
        encryption.update(
            f"{self.index}{self.timestamp}{self.merkle_root}{self.previous_hash}{self.nonce}".encode()
        )
        return encryption.hexdigest()

    @property
    def hash(self) -> str:
        return self.get_hash()


class BlockStorageInterface(Protocol):
    def get_all_blocks(self) -> list[Block]: ...
    def get_num_blocks(self) -> int: ...
    def add_block(self, block: Block) -> bool: ...
    def get_latest_block(self) -> Block: ...
    def drop_data(self) -> None: ...


class InMemoryBlockStorage:
    def __init__(self) -> None:
        self._blocks: list[Block] = []

    def get_all_blocks(self) -> list[Block]:
        return self._blocks.copy()

    def get_num_blocks(self) -> int:
        return len(self._blocks)

    def add_block(self, block: Block) -> bool:
        self._blocks.append(block)
        return True

    def get_latest_block(self) -> Block:
        return self._blocks[-1]

    def drop_data(self) -> None:
        self._blocks = []


class Blockchain:
    def __init__(
        self,
        difficulty: int = 4,
        mining_reward: int = 100,
        genesis_timestamp: Optional[dt.datetime] = None,
        block_storage: Optional[BlockStorageInterface] = None,
    ):
        self._pending_transactions: list[Transaction] = []
        self.difficulty: int = difficulty
        self.mining_reward: int = mining_reward

        self.address: str = "BlockchainMint"

        self.block_storage: BlockStorageInterface = (
            block_storage if block_storage is not None else InMemoryBlockStorage()
        )

        if genesis_timestamp is None:
            self._genesis_timestamp = dt.datetime(2024, 12, 14, tzinfo=dt.timezone.utc)
        else:
            self._genesis_timestamp = genesis_timestamp
        self.block_storage.add_block(self._mine_genesis_block())

    def __repr__(self):
        return (
            f"Blockchain(difficulty={self.difficulty}, mining_reward={self.mining_reward}, "
            f"blocks={self.block_storage.get_num_blocks()}, pending_transactions={len(self._pending_transactions)}"
        )

    def __str__(self):
        return self.__repr__()

    def get_pending_transactions(self) -> list[Transaction]:
        return self._pending_transactions.copy()

    def to_dict(self) -> dict[str, any]:
        return {
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "pending_transactions": [
                tsx.to_dict() for tsx in self._pending_transactions
            ],
            "blocks": [
                block.to_dict() for block in self.block_storage.get_all_blocks()
            ],
        }

    @staticmethod
    def from_dict(data: dict) -> "Blockchain":
        blockchain = Blockchain(
            difficulty=data["difficulty"], mining_reward=data["mining_reward"]
        )
        blockchain.block_storage.drop_data()
        for block_data in data["blocks"]:
            block = Block.from_dict(block_data)
            blockchain.block_storage.add_block(block)

        blockchain._pending_transactions = [
            Transaction.from_dict(tsx_data) for tsx_data in data["pending_transactions"]
        ]
        return blockchain

    def adress(self) -> None:
        return self.address

    def _mine_genesis_block(self) -> Block:
        # Cached nonce values for difficulties at the default genesis timestamp
        difficulty_to_nonce_map = {1: 1, 2: 80, 3: 14288, 4: 116009, 5: 139523}
        if (
            self._genesis_timestamp == dt.datetime(2024, 12, 15, tzinfo=dt.timezone.utc)
            and self.difficulty in difficulty_to_nonce_map
        ):
            genesis_block = Block(
                index=0,
                timestamp=self._genesis_timestamp,
                transactions=[],
                previous_hash="0" * 64,
                nonce=difficulty_to_nonce_map[self.difficulty],
            )
            logger.info(
                "Using cached genesis block for timestamp=%s, difficulty=%d",
                self._genesis_timestamp,
                self.difficulty,
            )
            return genesis_block

        genesis_block = Block(
            index=0,
            timestamp=self._genesis_timestamp,
            transactions=[],
            previous_hash="0" * 64,
            nonce=0,
        )
        while not genesis_block.hash.startswith("0" * self.difficulty):
            genesis_block.nonce += 1
        logger.info(f"{genesis_block.nonce=}")

        return genesis_block

    def add_transaction(self, transaction: Transaction) -> None:
        if transaction.sender_address == self.address:
            logger.warning(
                "Trying to add coinbase transactions via normal transaction."
            )
            return
        if not transaction.verify():
            logger.warning(f"Transaction verification failed: {transaction}")
            return
        logger.info(f"Added new transactions: {transaction}")
        self._pending_transactions.append(transaction)

    def add_block(self, block: Block) -> bool:
        if block.previous_hash != self.block_storage.get_latest_block().hash:
            logger.warning("Invalid Block: Previous Hash Mismatch.")
            return False

        if not block.hash.startswith("0" * self.difficulty):
            logger.warning("Invalid Block: Proof-Of-Work does not meet difficulty")
            return False

        self.block_storage.add_block(block)
        logger.info("Block successfully added to the chain.")
        return True

    def mine_block(self, miner_address: str) -> bool:
        if len(self._pending_transactions) == 0:
            logger.info("No more transactions pending, so no block will be mined.")
            return False

        self.mint(miner_address, self.mining_reward)

        new_block = Block(
            index=self.block_storage.get_num_blocks(),
            timestamp=dt.datetime.now(tz=dt.timezone.utc),
            transactions=self._pending_transactions.copy(),
            previous_hash=self.block_storage.get_latest_block().hash,
            nonce=0,
        )

        while not new_block.hash.startswith("0" * self.difficulty):
            logger.debug("%12d - Failed to mine block, block hash: ", new_block.hash)
            new_block.nonce += 1
        logger.info(f"Successfully mined block {new_block}")

        if not self.add_block(new_block):
            logger.error("Failed to add the block after mining!")
            return False

        self._pending_transactions.clear()
        return True

    def is_valid(self) -> bool:
        blocks = self.block_storage.get_all_blocks()
        for b in blocks:
            if not b.hash.startswith("0" * self.difficulty):
                return False

        for b1, b2 in zip(blocks[:-1], blocks[1:]):
            if b2.previous_hash != b1.hash:
                return False
        return True

    def get_adress_balance(self, address: str) -> int:
        blocks = self.block_storage.get_all_blocks()
        balance = 0
        for block in blocks:
            for tsx in block._transactions:
                if tsx.sender_address == address:
                    balance -= tsx.amount
                if tsx.receiver_address == address:
                    balance += tsx.amount
        return balance

    def mint(self, address: str, amount: int) -> None:
        coinbase_transaction = Transaction(
            sender_address=self.address, receiver_address=address, amount=amount
        )
        self._pending_transactions = [coinbase_transaction] + self._pending_transactions
        logger.info(f"Minted {amount} coins, awarding them to {address}.")


class Miner:
    def __init__(self, wallet: Wallet, blockchain: Blockchain):
        self.wallet = wallet
        self.blockchain = blockchain

    def mine_block(self) -> bool:
        return self.blockchain.mine_block(self.wallet.address)

    def get_balance(self) -> int:
        return self.blockchain.get_adress_balance(self.wallet.address)
