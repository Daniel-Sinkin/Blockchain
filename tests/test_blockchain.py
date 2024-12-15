import datetime as dt

from src.blockchain import Blockchain


def test_blockchain_init() -> None:
    for genesis_timestamp in [
        dt.datetime(2024, 12, 15, tzinfo=dt.timezone.utc),
        dt.datetime(2024, 12, 14, tzinfo=dt.timezone.utc),
    ]:
        for difficulty in [1, 2, 3, 4, 5]:
            bc = Blockchain(
                difficulty=difficulty,
                genesis_timestamp=genesis_timestamp,
            )
            assert len(bc.get_pending_transactions()) == 0

            assert len(bc.blocks) == 1
            genesis_block = bc.blocks[0]
            assert genesis_block.hash.startswith("0" * bc.difficulty)
            assert len(genesis_block.get_transactions()) == 0
            assert genesis_block.previous_hash == "0" * 64
            assert genesis_block.index == 0


def test_blockchain_mining() -> None:
    bc = Blockchain(difficulty=4, mining_reward=100)
    genesis_block = bc.blocks[0]
    bc.create_and_add_transaction(sender=bc.address, receiver="Alice", amount=30)
    assert len(bc.get_pending_transactions()) == 1
    bc.create_and_add_transaction(sender=bc.address, receiver="Bob", amount=100)
    assert len(bc.get_pending_transactions()) == 2

    assert bc.get_adress_balance("Alice") == 0
    assert bc.get_adress_balance("Bob") == 0

    bc.mine_block(miner_address="Mr. Miner")
    assert len(bc.get_pending_transactions()) == 0

    assert bc.get_adress_balance("Alice") == 30
    assert bc.get_adress_balance("Bob") == 100
    assert bc.get_adress_balance("Mr. Miner") == 100

    assert len(bc.blocks) == 2
    new_block = bc.blocks[1]
    new_block.index == 1
    len(new_block.get_transactions()) == 3  # 2 transactions + 1 for the miner
    new_block.previous_hash == genesis_block.hash

    bc.mine_block(miner_address="Miner Jr.")
    assert len(bc.blocks) == 2

    assert bc.get_adress_balance("Alice") == 30
    assert bc.get_adress_balance("Bob") == 100
    assert bc.get_adress_balance("Mr. Miner") == 100
    assert bc.get_adress_balance("Miner Jr.") == 0

    bc.create_and_add_transaction(sender="Bob", receiver="Alice", amount=40)
    assert len(bc.get_pending_transactions()) == 1
    bc.mine_block(miner_address="Mr. Miner")
    assert len(bc.blocks) == 3
    assert bc.blocks[2].index == 2
    assert len(bc.blocks[2].get_transactions()) == 2

    assert bc.get_adress_balance("Alice") == 70
    assert bc.get_adress_balance("Bob") == 60
    assert bc.get_adress_balance("Mr. Miner") == 2 * 100
    assert bc.get_adress_balance("Miner Jr.") == 0
    assert bc.get_adress_balance(bc.address) == -330
