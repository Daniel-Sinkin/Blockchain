import datetime as dt
import hashlib
from logging import INFO as LOG_INFO_LEVEL
from logging import Logger
from typing import Optional

logger = Logger(__name__)
logger.setLevel(LOG_INFO_LEVEL)


class Transaction:
    def __init__(self, sender: str, receiver: str, amount: int):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

    def __repr__(self):
        return f"Transaction({self.sender},{self.receiver},{self.amount})"

    def __str__(self):
        return self.__repr__()

    def format(self) -> str:
        return f"{self.sender} sends {self.amount} DSC to {self.receiver}."

    def to_hashable(self) -> str:
        return f"{self.sender}{self.receiver}{self.amount}"

    def to_hashable_bytes(self) -> bytes:
        return self.to_hashable().encode()


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
            else:  # If it's the last hash and no pair, duplicate it
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
            f"transactions={self._transactions!r}, previous_hash={self.previous_hash!r}, nonce={self.nonce})"
        )

    def __str__(self):
        return (
            f"Block {self.index}:\n"
            f"Timestamp: {self.timestamp}\n"
            f"Transactions: {self._transactions}\n"
            f"Previous Hash: {self.previous_hash}\n"
            f"Nonce: {self.nonce}\n"
            f"Hash: {self.hash}"
        )

    def get_transactions(self) -> list[Transaction]:
        return self._transactions.copy()

    def format(self) -> str:
        return (
            f"Block {self.index}:\n"
            f"  Timestamp: {self.timestamp}\n"
            f"  Transactions: {self._transactions})\n"
            f"  Previous Hash: {self.previous_hash}\n"
            f"  Nonce: {self.nonce}\n"
            f"  Hash: {self.hash}"
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


class Blockchain:
    def __init__(
        self,
        difficulty: int = 4,
        mining_reward: int = 100,
        genesis_timestamp: Optional[dt.datetime] = None,
    ):
        self._pending_transactions: list[Transaction] = []
        self.difficulty: int = difficulty
        self.mining_reward: int = mining_reward

        self.address: str = "BlockchainSystem"

        if genesis_timestamp is None:
            self._genesis_timestamp = dt.datetime(2024, 12, 14, tzinfo=dt.timezone.utc)
        else:
            self._genesis_timestamp = genesis_timestamp
        self.blocks: list[Block] = [self._mine_genesis_block()]

    def __repr__(self):
        return (
            f"Blockchain(difficulty={self.difficulty}, mining_reward={self.mining_reward}, "
            f"blocks={len(self.blocks)}, pending_transactions={len(self._pending_transactions)})"
        )

    def __str__(self):
        block_summaries = "\n".join(block.format() for block in self.blocks)
        return (
            f"Blockchain:\n"
            f"Difficulty: {self.difficulty}\n"
            f"Mining Reward: {self.mining_reward}\n"
            f"Blocks:\n{block_summaries}\n"
            f"Pending Transactions: {', '.join(self._pending_transactions) if self._pending_transactions else 'None'}"
        )

    def get_pending_transactions(self) -> list[Transaction]:
        return self._pending_transactions.copy()

    def format(self) -> str:
        block_details = "\n\n".join(block.format() for block in self.blocks)
        return (
            f"Blockchain Overview:\n"
            f"  Difficulty: {self.difficulty}\n"
            f"  Mining Reward: {self.mining_reward}\n"
            f"  Pending Transactions: {', '.join(self._pending_transactions) if self._pending_transactions else 'None'}\n"
            f"  Blocks:\n\n{block_details}"
        )

    def adress(self) -> None:
        return self.address

    def _mine_genesis_block(self) -> Block:
        # Could hardcode the result from this rather than recompute.

        genesis_block = Block(
            index=0,
            timestamp=self._genesis_timestamp,
            transactions=[],
            previous_hash="0" * 64,
            nonce=0,
        )
        while not genesis_block.hash.startswith("0" * self.difficulty):
            genesis_block.nonce += 1

        return genesis_block

    def add_transaction(self, transaction: Transaction) -> None:
        logger.info(f"Added new transactions: {transaction.format()}")
        self._pending_transactions.append(transaction)

    def create_and_add_transaction(
        self, sender: str, receiver: str, amount: int
    ) -> None:
        self.add_transaction(
            Transaction(sender=sender, receiver=receiver, amount=amount)
        )

    def add_block(self, block: Block) -> bool:
        if block.previous_hash != self.blocks[-1].hash:
            logger.warning("Invalid Block: Previous Hash Mismatch.")
            return False

        if not block.hash.startswith("0" * self.difficulty):
            logger.warning("Invalid Block: Proof-Of-Work does not meet difficulty")
            return False

        self.blocks.append(block)
        logger.info("Block successfully added to the chain.")
        return True

    def mine_block(self, miner_address: str) -> bool:
        if len(self._pending_transactions) == 0:
            logger.info("No more transactions pending, so no block will be mined.")
            return False

        self.create_and_add_transaction(
            sender=self.address, receiver=miner_address, amount=self.mining_reward
        )

        new_block = Block(
            index=len(self.blocks),
            timestamp=dt.datetime.now(tz=dt.timezone.utc),
            transactions=self._pending_transactions.copy(),
            previous_hash=self.blocks[-1].hash,
            nonce=0,
        )

        while not new_block.hash.startswith("0" * self.difficulty):
            logger.debug("%12d - Failed to mine block, block hash: ", new_block.hash)
            new_block.nonce += 1
        logger.info(f"Successfully mined block {new_block.format()}")

        if not self.add_block(new_block):
            logger.error("Failed to add the block after mining!")
            return False

        self._pending_transactions.clear()
        return True

    def is_valid(self) -> bool:
        for b in self.blocks:
            if not b.hash.startswith("0" * self.difficulty):
                return False

        for b1, b2 in zip(self.blocks[:-1], self.blocks[1:]):
            if b2.previous_hash != b1.hash:
                return False
        return True

    def get_adress_balance(self, address: str) -> int:
        balance = 0
        for block in self.blocks:
            for tsx in block._transactions:
                if tsx.sender == address:
                    balance -= tsx.amount
                if tsx.receiver == address:
                    balance += tsx.amount
        return balance

    def resolve_conflits(self, other_chains: list["Blockchain"]) -> bool: ...
