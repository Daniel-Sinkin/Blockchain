import datetime as dt
from copy import deepcopy

import pytest

from src.blockchain import Blockchain, Transaction, Wallet


@pytest.fixture
def prepared_blockchain() -> Blockchain:
    blockchain = Blockchain(
        difficulty=2,
        mining_reward=50,
        genesis_timestamp=dt.datetime(2024, 12, 15, tzinfo=dt.timezone.utc),
    )

    wallet1 = Wallet()
    wallet2 = Wallet()

    tx1 = Transaction(
        sender_address=wallet1.address, receiver_address=wallet2.address, amount=10
    )
    tx1.sign(wallet1)
    blockchain.add_transaction(tx1)

    tx2 = Transaction(
        sender_address=wallet2.address, receiver_address=wallet1.address, amount=5
    )
    tx2.sign(wallet2)
    blockchain.add_transaction(tx2)

    miner_wallet = Wallet()
    blockchain.mine_block(miner_wallet.address)

    tx3 = Transaction(
        sender_address=wallet1.address, receiver_address=wallet2.address, amount=20
    )
    tx3.sign(wallet1)
    blockchain.add_transaction(tx3)
    blockchain.mine_block(miner_wallet.address)

    return blockchain


def test_blockchain_serialization_deserialization(prepared_blockchain) -> None:
    original_dict = prepared_blockchain.to_dict()

    serialized_copy = deepcopy(original_dict)

    reconstructed_blockchain = Blockchain.from_dict(serialized_copy)

    reconstructed_dict = reconstructed_blockchain.to_dict()

    assert reconstructed_dict["difficulty"] == original_dict["difficulty"]
    assert reconstructed_dict["mining_reward"] == original_dict["mining_reward"]

    assert len(reconstructed_dict["pending_transactions"]) == len(
        original_dict["pending_transactions"]
    )
    for orig_tx, recon_tx in zip(
        original_dict["pending_transactions"],
        reconstructed_dict["pending_transactions"],
    ):
        assert orig_tx == recon_tx

    assert len(reconstructed_dict["blocks"]) == len(original_dict["blocks"])
    for orig_block, recon_block in zip(
        original_dict["blocks"], reconstructed_dict["blocks"]
    ):
        assert orig_block["index"] == recon_block["index"]
        assert orig_block["timestamp"] == recon_block["timestamp"]
        assert orig_block["previous_hash"] == recon_block["previous_hash"]
        assert orig_block["nonce"] == recon_block["nonce"]

        assert len(orig_block["transactions"]) == len(recon_block["transactions"])
        for orig_tx, recon_tx in zip(
            orig_block["transactions"], recon_block["transactions"]
        ):
            assert orig_tx == recon_tx


def test_empty_blockchain_serialization_deserialization():
    blockchain = Blockchain(
        difficulty=1,
        mining_reward=10,
        genesis_timestamp=dt.datetime(2024, 12, 15, tzinfo=dt.timezone.utc),
    )

    original_dict = blockchain.to_dict()
    serialized_copy = deepcopy(original_dict)
    reconstructed = Blockchain.from_dict(serialized_copy)

    assert (
        reconstructed.to_dict()["pending_transactions"]
        == original_dict["pending_transactions"]
    )
    assert reconstructed.to_dict()["blocks"] == original_dict["blocks"]
    assert reconstructed.to_dict()["difficulty"] == original_dict["difficulty"]
    assert reconstructed.to_dict()["mining_reward"] == original_dict["mining_reward"]
    assert reconstructed.is_valid() == blockchain.is_valid()
