import datetime as dt

from src.blockchain import Blockchain, Transaction, Wallet


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
    alice = Wallet()
    bob = Wallet()
    miner = Wallet()

    bc = Blockchain(difficulty=4, mining_reward=100)
    assert len(bc.blocks) == 1

    bc.mint(alice.address, 300)
    bc.mint(bob.address, 200)

    assert bc.get_adress_balance(alice.address) == 0
    assert bc.get_adress_balance(bob.address) == 0
    assert bc.get_adress_balance(miner.address) == 0

    assert bc.mine_block(miner.address)
    assert len(bc.blocks) == 2

    assert bc.get_adress_balance(alice.address) == 300
    assert bc.get_adress_balance(bob.address) == 200
    assert bc.get_adress_balance(miner.address) == 100

    tsx = Transaction(
        sender_address=alice.address, receiver_address=bob.address, amount=150
    )
    bc.add_transaction(tsx)  # Not signed
    bc.mine_block(miner.address)
    assert bc.get_adress_balance(miner.address) == 100
    assert len(bc.blocks) == 2

    tsx.sign(bob)  # Wrong
    bc.add_transaction(tsx)  # Not signed
    bc.mine_block(miner.address)
    assert bc.get_adress_balance(miner.address) == 100
    assert len(bc.blocks) == 2

    tsx.sign(alice)
    bc.add_transaction(tsx)
    bc.mine_block(miner.address)
    assert bc.get_adress_balance(miner.address) == 200
    assert len(bc.blocks) == 3

    assert bc.get_adress_balance(alice.address) == 150
    assert bc.get_adress_balance(bob.address) == 350
