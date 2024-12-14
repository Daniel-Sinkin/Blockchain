from src.blockchain import Blockchain


def main() -> None:
    bc = Blockchain(difficulty=4, mining_reward=100)
    bc.create_and_add_transaction(sender="Alice", receiver="Bob", amount=50)
    bc.create_and_add_transaction(sender="Charlie", receiver="Alice", amount=20)

    bc.mine_block(miner_address="Miner123")
    bc.mine_block(miner_address="Miner456")

    bc.pprint()


if __name__ == "__main__":
    main()
