import datetime as dt
import hashlib

# Toy blockchain to get a first impression, mostly inspired by
# https://medium.com/swlh/is-it-hard-to-build-a-blockchain-from-scratch-2662e9b873b7


class Block:
    def __init__(
        self, index: int, timestamp: dt.datetime, data: str, previous_hash: str
    ):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash

    def __repr__(self):
        return f"Block({self.index},{self.timestamp},{self.data},{self.previous_hash})"

    def __str__(self):
        return self.__repr__()

    def format(self) -> str:
        return f"Block #{self.index} [{self.timestamp}]\nHash: {self.hash}\nPrevious Hash: {self.previous_hash}\nData: {self.data}"

    def pprint(self) -> None:
        print(self.format())

    def get_hash(self) -> str:
        encryption = hashlib.sha256()
        encryption.update(
            f"{self.index}{self.timestamp}{self.data}{self.previous_hash}".encode()
        )
        return encryption.hexdigest()

    @property
    def hash(self) -> str:
        return self.get_hash()

    @staticmethod
    def create_genesis_block() -> "Block":
        return Block(
            index=0,
            timestamp=dt.datetime.now(tz=dt.tcimezone.utc),
            data="genesis block transaction",
            previous_hash=" ",
        )

    def create_next_block(self) -> "Block":
        new_index = self.index + 1
        return Block(
            index=new_index,
            timestamp=dt.datetime.now(dt.timezone.utc),
            data=f"Transaction {new_index}",
            previous_hash=self.hash,
        )


def main() -> None:
    blockchain = [Block.create_genesis_block()]
    for _ in range(5):
        blockchain.append(blockchain[-1].reate_next_block())

    for block in blockchain[1:]:  # Don't print genesis block
        block.pprint()
        print()


"""
Block #1 [2024-12-14 21:33:38.915825+00:00]
Hash: 60cefb3e041d6ba8e9fbefb41b8440fff800aa0d0d155e4a1cb7e9766dd22ff9
Previous Hash: 903496d86acdc3a765892a2b58112686f9e1c188c973e120e71bab82524758a6
Data: Transaction 1

Block #2 [2024-12-14 21:33:38.915847+00:00]
Hash: 0c8b0991be5f54e0bd6ee45d77788f8f615f1158c4e25aa4c259bae9d9ac8836
Previous Hash: 60cefb3e041d6ba8e9fbefb41b8440fff800aa0d0d155e4a1cb7e9766dd22ff9
Data: Transaction 2

Block #3 [2024-12-14 21:33:38.915855+00:00]
Hash: ba9094cfe24b45d8018f0a55e2d9ba090dc6635f84d0f9693a2f405780b2cd61
Previous Hash: 0c8b0991be5f54e0bd6ee45d77788f8f615f1158c4e25aa4c259bae9d9ac8836
Data: Transaction 3

Block #4 [2024-12-14 21:33:38.915861+00:00]
Hash: 5fc23bece5bf0257366b28a627831f403c8442ac97aa3b1febfe7d3ca6b6aa65
Previous Hash: ba9094cfe24b45d8018f0a55e2d9ba090dc6635f84d0f9693a2f405780b2cd61
Data: Transaction 4

Block #5 [2024-12-14 21:33:38.915865+00:00]
Hash: e9224eb0d172511b9885be431d6a134189e399f00e67eed87e0da64d21c9bf8b
Previous Hash: 5fc23bece5bf0257366b28a627831f403c8442ac97aa3b1febfe7d3ca6b6aa65
Data: Transaction 5
"""

if __name__ == "__main__":
    main()
