import datetime as dt

from src.blockchain import Blockchain


def test_blockchain_init() -> None:
    for difficulty in [1, 2, 3, 4]:
        bc = Blockchain(
            difficulty=difficulty,
            genesis_timestamp=dt.datetime(2024, 12, 15, tzinfo=dt.timezone.utc),
        )
        assert len(bc.get_pending_transactions()) == 0

        assert len(bc.blocks) == 1
        genesis_block = bc.blocks[0]
        assert genesis_block.hash.startswith("0" * bc.difficulty)
        assert len(genesis_block.get_transactions()) == 0
        assert genesis_block.previous_hash == "0" * 64
        assert genesis_block.index == 0


def test_blockchain_mining() -> None:
    bc = Blockchain(difficulty=4)
    genesis_block = bc.blocks[0]
    bc.create_and_add_transaction(sender=bc.address, receiver="Alice", amount=30)
    assert len(bc.get_pending_transactions()) == 1
    bc.create_and_add_transaction(sender=bc.address, receiver="Bob", amount=100)
    assert len(bc.get_pending_transactions()) == 2

    bc.mine_block(miner_address="MrMiner")
    assert len(bc.get_pending_transactions()) == 0

    assert len(bc.blocks) == 2
    new_block = bc.blocks[1]
    new_block.index == 1
    len(new_block.get_transactions()) == 3  # 2 transactions + 1 for the miner
    new_block.previous_hash == genesis_block.hash

    bc.mine_block(miner_address="MrsMiner")
    assert len(bc.blocks) == 2

    bc.create_and_add_transaction(sender="Bob", receiver="Alice", amount=40)
    assert len(bc.get_pending_transactions()) == 1
    bc.mine_block(miner_address="Miner Jr.")
    assert len(bc.blocks) == 3
    assert bc.blocks[2].index == 2
    assert len(bc.blocks[2].get_transactions()) == 2  # 1 transaction + 1 for the miner
