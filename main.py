import json

import pandas as pd

from src.blockchain import Blockchain, Transaction, Wallet


def get_balances(
    bc: Blockchain, alice: Wallet, bob: Wallet, miner: Wallet
) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "User": ["Alice", "Bob", "Miner"],
            "Address": [
                f"{x[:6]}...{x[-6:]}"
                for x in [alice.address, bob.address, miner.address]
            ],
            "Balance (DSC)": [
                bc.get_adress_balance(alice.address),
                bc.get_adress_balance(bob.address),
                bc.get_adress_balance(miner.address),
            ],
        }
    )


def main() -> None:
    bc = Blockchain(mining_reward=128)

    alice = Wallet()
    bob = Wallet()
    miner = Wallet()

    print("After Initialization")
    print("Blockchain:")
    print(json.dumps(bc.to_dict(), indent=4))
    print(get_balances(bc, alice, bob, miner))
    print()

    print("System gives Alice 2000 DSC and Bob 3000 DCS.")
    bc.mint(alice.address, 2000)
    bc.mint(bob.address, 3000)
    bc.mine_block(miner.address)

    print("After Initialization")
    print("Blockchain:")
    print(json.dumps(bc.to_dict(), indent=4))
    print(get_balances(bc, alice, bob, miner))

    print("Alice gives Bob 777 DSC")
    tsx = Transaction(
        sender_address=alice.address, receiver_address=bob.address, amount=777
    )
    tsx.sign(alice)
    bc.add_transaction(tsx)
    bc.mine_block(miner.address)

    print("After Initialization")
    print("Blockchain:")
    print(json.dumps(bc.to_dict(), indent=4))
    print(get_balances(bc, alice, bob, miner))
    print()


if __name__ == "__main__":
    main()
