import asyncio
import concurrent.futures
import itertools
import os
import struct
import sys
from typing import *

import aiohttp

from blockchain import BlockchainStorage, Wallet, PRIVATE_KEY_PATH, MINIMUM_DIFFICULTY_LEVEL, MessageType, Message, \
    Transaction

DATABASE_PATH = os.getenv('DATABASE_PATH', './bs-client.db')  # TODO find another place to store it
BLOCKCHAIN = None


def call_with_global_blockchain(method, *args, **kwargs):
    if BLOCKCHAIN is None:
        raise ValueError("Blockchain is not properly initialized; are you a worker?")
    return method(BLOCKCHAIN, *args, **kwargs)


def initialize_worker(_x):
    global BLOCKCHAIN
    os.setpgid(0, 0)  # Prevent receiving SIGINT inside worker
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)
    BLOCKCHAIN = BlockchainStorage(DATABASE_PATH)


async def main():
    """The main function that connects to the blockchain network and handles
all message exchanges. A wise man once said that inside every
sufficiently complicated program there is an ad-hoc,
informally-specified, bug-ridden state machine.
    """
    # TODO make state machine more explicit
    server_uri = os.getenv('SERVER_URI', 'http://localhost:8080/ws')
    bs = BlockchainStorage(DATABASE_PATH)  # Just to catch existing errors in the DB
    del bs

    wallet = Wallet.load_from_disk()
    if wallet is None:
        print("No wallet found; a wallet will be created for you at " + PRIVATE_KEY_PATH)
        wallet = Wallet.new()

    loop = asyncio.get_event_loop()

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(server_uri, heartbeat=30, max_msg_size=0) as ws:
            async def send(message: Message):
                print('DEBUG: about to send message %r' % message)
                await ws.send_bytes(message.serialize_into_bytes())

            with concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0]) as pool:

                has_finished_requesting_chains = asyncio.Event()
                has_finished_receiving_chains = asyncio.Event()
                has_finished_receiving_tentative_txns = asyncio.Event()
                get_block_inflight_count = 0
                is_ready = asyncio.Event()
                queued_new_blocks = []  # newly announced blocks received when we were not yet ready
                queued_txns = []  # newly announced tentative transactions when we were not yet ready
                difficulty_level = MINIMUM_DIFFICULTY_LEVEL

                await send(Message(MessageType.GetCurrentDifficultyLevel))
                await send(Message(MessageType.GetLongestChain))

                async for msg in ws:
                    msg = cast(aiohttp.WSMessage, msg)
                    if msg.type != aiohttp.WSMsgType.BINARY:
                        print("WARNING: received nonsense data: " + repr(msg.data), file=sys.stderr)
                        continue
                    try:
                        m = Message.deserialize_from_bytes(msg.data)
                    except (ValueError, struct.error):
                        print("WARNING: received nonsense data: " + repr(msg.data), file=sys.stderr)
                        continue
                    if m.message_type is MessageType.ReplyDifficultyLevel:
                        difficulty_level = m.arg
                    elif m.message_type is MessageType.ReplyLongestChain:
                        their_longest_chain = sorted(m.arg, key=lambda x: x[1])

                        async def request_all_missing():
                            our_longest_chain = await loop.run_in_executor(pool, call_with_global_blockchain,
                                                                           BlockchainStorage.get_longest_chain)
                            our_longest_chain.sort(key=lambda x: x[1])
                            for their, our in itertools.zip_longest(their_longest_chain, our_longest_chain):
                                if their == our:
                                    continue
                                elif their is None:
                                    break
                                else:
                                    nonlocal get_block_inflight_count
                                    get_block_inflight_count += 1
                                    await send(Message(MessageType.GetBlockByHash, their[0]))
                            has_finished_requesting_chains.set()

                        async def on_finish_receiving_all_missing():
                            await has_finished_receiving_chains.wait()
                            await send(Message(MessageType.GetTentativeTransactions))

                        loop.create_task(request_all_missing())
                        loop.create_task(on_finish_receiving_all_missing())
                    elif m.message_type is MessageType.ReplyBlockByHash:
                        async def receive_block_ignore_errors():
                            try:
                                await loop.run_in_executor(pool, call_with_global_blockchain,
                                                           BlockchainStorage.receive_block, m.arg)
                            except ValueError:
                                pass
                            nonlocal get_block_inflight_count
                            get_block_inflight_count -= 1
                            if get_block_inflight_count == 0 and has_finished_requesting_chains.is_set():
                                has_finished_receiving_chains.set()

                        loop.create_task(receive_block_ignore_errors())
                    elif m.message_type is MessageType.ReplyTentativeTransactions:
                        async def receive_txns_ignore_errors():
                            for t in m.arg:
                                t = cast(Transaction, t)
                                try:
                                    await loop.run_in_executor(pool, call_with_global_blockchain,
                                                               BlockchainStorage.receive_tentative_transaction, t)
                                except ValueError:
                                    pass
                            has_finished_receiving_tentative_txns.set()

                        loop.create_task(receive_txns_ignore_errors())
                    elif m.message_type is MessageType.AnnounceNewMinedBlock:
                        if is_ready.is_set():
                            raise NotImplementedError
                        else:
                            queued_new_blocks.append(m.arg)
                    elif m.message_type is MessageType.AnnounceNewTentativeTransaction:
                        if is_ready.is_set():
                            raise NotImplementedError
                        else:
                            queued_txns.append(m.arg)
                    else:
                        print("WARNING: received nonsense data: " + repr(msg.data), file=sys.stderr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
