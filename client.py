import asyncio
import concurrent.futures
import itertools
import os
import struct
import sys
from typing import *

import aiohttp

from blockchain import BlockchainStorage, Wallet, PRIVATE_KEY_PATH, MINIMUM_DIFFICULTY_LEVEL, MessageType, Message, \
    Transaction, Block

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
all message exchanges.
    """
    server_uri = os.getenv('SERVER_URI', 'http://localhost:8080/ws')
    bs = BlockchainStorage(DATABASE_PATH)  # Just to catch existing errors in the DB
    del bs

    wallet = Wallet.load_from_disk()
    if wallet is None:
        print("No wallet found; a wallet will be created for you at " + PRIVATE_KEY_PATH)
        wallet = Wallet.new()

    loop = asyncio.get_event_loop()
    with concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0], max_workers=3) as pool:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(server_uri, heartbeat=30, max_msg_size=0) as ws:
                is_ready = False
                queued_new_blocks = []  # newly announced blocks received when we were not yet ready
                queued_txns = []  # newly announced tentative transactions when we were not yet ready
                difficulty_level = MINIMUM_DIFFICULTY_LEVEL

                async def send(ty: MessageType, arg=None) -> None:
                    message = Message(ty, arg)
                    await ws.send_bytes(message.serialize_into_bytes())

                def expect(message: Message, ty: MessageType) -> Message:
                    if message.message_type is not ty:
                        raise ValueError("Unexpected message type from server:", message.message_type)
                    return message

                async def did_receive_block(b: Block):
                    try:
                        await loop.run_in_executor(pool, call_with_global_blockchain, BlockchainStorage.receive_block,
                                                   b)
                    except ValueError:
                        pass

                async def did_receive_transaction(t: Transaction):
                    try:
                        await loop.run_in_executor(pool, call_with_global_blockchain,
                                                   BlockchainStorage.receive_tentative_transaction, t)
                    except ValueError:
                        pass

                async def initialize() -> AsyncGenerator[None, Message]:
                    await send(MessageType.GetCurrentDifficultyLevel)
                    received = expect((yield), MessageType.ReplyDifficultyLevel)
                    nonlocal difficulty_level
                    difficulty_level = received.arg

                    await send(MessageType.GetLongestChain)
                    received = expect((yield), MessageType.ReplyLongestChain)
                    their_longest_chain = cast(List[Tuple[bytes, int]], received.arg)
                    their_longest_chain.sort(key=lambda k: k[1])
                    our_longest_chain = await loop.run_in_executor(pool, call_with_global_blockchain,
                                                                   BlockchainStorage.get_longest_chain)
                    our_longest_chain.sort(key=lambda x: x[1])
                    for theirs, ours in itertools.zip_longest(their_longest_chain, our_longest_chain):
                        if theirs == ours:
                            continue
                        elif theirs is None:
                            break
                        else:
                            await send(MessageType.GetBlockByHash, theirs[0])
                            received = expect((yield), MessageType.ReplyBlockByHash)
                            await did_receive_block(received.arg)

                    await send(MessageType.GetTentativeTransactions)
                    received = expect((yield), MessageType.ReplyTentativeTransactions)
                    for t in received.arg:
                        t = cast(Transaction, t)
                        await did_receive_transaction(t)

                initializer = initialize()
                await initializer.asend(None)
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

                    if m.message_type is MessageType.AnnounceNewMinedBlock:
                        if is_ready:
                            await did_receive_block(m.arg)
                        else:
                            queued_new_blocks.append(m.arg)
                    elif m.message_type is MessageType.AnnounceNewTentativeTransaction:
                        if is_ready:
                            await did_receive_transaction(m.arg)
                        else:
                            queued_txns.append(m.arg)
                    elif not is_ready:
                        try:
                            await initializer.asend(m)
                        except StopAsyncIteration:
                            is_ready = True
                            for b in queued_new_blocks:
                                await did_receive_block(b)
                            for t in queued_txns:
                                await did_receive_transaction(t)
                            queued_new_blocks = []
                            queued_txns = []
                            print("Ready!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
