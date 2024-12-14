import datetime as dt
import hashlib


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

    def pprint(self) -> None:
        print(self.format())


def compute_merkle_root(transactions: list[Transaction]) -> str:
    raise NotImplementedError


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
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        try:
            self.merkle_root = self.merkle_root()
        except NotImplementedError:
            self.merkle_root = None

    def __repr__(self):
        return (
            f"Block(index={self.index}, timestamp={self.timestamp!r}, "
            f"transactions={self.transactions!r}, previous_hash={self.previous_hash!r}, nonce={self.nonce})"
        )

    def __str__(self):
        return (
            f"Block {self.index}:\n"
            f"Timestamp: {self.timestamp}\n"
            f"Transactions: {self.transactions}\n"
            f"Previous Hash: {self.previous_hash}\n"
            f"Nonce: {self.nonce}\n"
            f"Hash: {self.hash}"
        )

    def format(self) -> str:
        return (
            f"Block {self.index}:\n"
            f"  Timestamp: {self.timestamp}\n"
            f"  Transactions: {self.transactions})\n"
            f"  Previous Hash: {self.previous_hash}\n"
            f"  Nonce: {self.nonce}\n"
            f"  Hash: {self.hash}"
        )

    def pprint(self) -> None:
        print(self.format())

    def compute_merkle_root(self) -> str:
        compute_merkle_root(self.transactions)

    def get_hash(self) -> str:
        encryption = hashlib.sha256()

        if self.merkle_root is None:
            tsxs_string = "".join(
                f"{tsx.sender}{tsx.receiver}{tsx.amount}" for tsx in self.transactions
            )
            encryption.update(
                f"{self.index}{self.timestamp}{tsxs_string}{self.previous_hash}{self.nonce}".encode()
            )
        else:
            encryption.update(
                f"{self.index}{self.timestamp}{self.merkle_root}{self.previous_hash}{self.nonce}".encode()
            )
        return encryption.hexdigest()

    @property
    def hash(self) -> str:
        return self.get_hash()


class Blockchain:
    def __init__(self, difficulty: int = 4, mining_reward: int = 100):
        self._pending_transactions: list[Transaction] = []
        self.difficulty: int = difficulty
        self.mining_reward: int = mining_reward

        self._address: str = "BlockchainSystem"

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

    def format(self) -> str:
        block_details = "\n\n".join(block.format() for block in self.blocks)
        return (
            f"Blockchain Overview:\n"
            f"  Difficulty: {self.difficulty}\n"
            f"  Mining Reward: {self.mining_reward}\n"
            f"  Pending Transactions: {', '.join(self._pending_transactions) if self._pending_transactions else 'None'}\n"
            f"  Blocks:\n\n{block_details}"
        )

    def pprint(self) -> None:
        print(self.format())

    def adress(self) -> None:
        return self._address

    def _mine_genesis_block(self) -> Block:
        # Could hardcode the result from this rather than recompute.
        genesis_timestamp = dt.datetime(2024, 12, 14, tzinfo=dt.timezone.utc)
        nonce = 0

        genesis_block = Block(
            index=0,
            timestamp=genesis_timestamp,
            transactions=[],
            previous_hash="0" * 64,
            nonce=nonce,
        )

        while not genesis_block.hash.startswith("0" * self.difficulty):
            nonce += 1
            genesis_block = Block(
                index=0,
                timestamp=genesis_timestamp,
                transactions=[],
                previous_hash="0" * 64,
                nonce=nonce,
            )

        return genesis_block

    def add_transaction(self, transaction: Transaction) -> None:
        print("Added new transactions:")
        print(f'    "{transaction.format()}"')
        self._pending_transactions.append(transaction)

    def create_and_add_transaction(
        self, sender: str, receiver: str, amount: int
    ) -> None:
        self.add_transaction(
            Transaction(sender=sender, receiver=receiver, amount=amount)
        )

    def add_block(self, block: Block) -> bool:
        if block.previous_hash != self.blocks[-1].hash:
            print("Invalid Block: Previous Hash Mismatch.")
            return False

        if not block.hash.startswith("0" * self.difficulty):
            print("Invalid Block: Proof-Of-Work does not meet difficulty")
            return False

        self.blocks.append(block)
        print("Block successfully added to the chain.")
        return True

    def mine_block(self, miner_address: str, verbose: bool = False) -> bool:
        if len(self._pending_transactions) == 0:
            print("No more transactions pending, so no block will be mined.")
            return False

        self.create_and_add_transaction(
            sender=self._address, receiver=miner_address, amount=self.mining_reward
        )

        new_block = Block(
            index=len(self.blocks),
            timestamp=dt.datetime.now(tz=dt.timezone.utc),
            transactions=self._pending_transactions.copy(),
            previous_hash=self.blocks[-1].hash,
            nonce=0,
        )

        while not new_block.hash.startswith("0" * self.difficulty):
            if verbose:
                print(
                    f"{new_block.nonce:12} - Failed to mine block, block hash: {new_block.hash}"
                )
            new_block.nonce += 1
        print(
            f"Block mined successfully after {new_block.nonce} attempts: Hash = '{new_block.hash}'."
        )

        if not self.add_block(new_block):
            print("Failed to add the block after mining!")
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

    def get_adress_balance(self, adress: str) -> int:
        balance = 0
        for block in self.blocks:
            for tsx in block.transactions:
                if tsx.sender == adress:
                    balance -= tsx.amount
                if tsx.receiver == adress:
                    balance += tsx.amount
        return balance

    def resolve_conflits(self, other_chains: list["Blockchain"]) -> bool: ...
