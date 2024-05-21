import asyncio
import aiohttp
import uuid
import os
import sys
import logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG").upper()
root = logging.getLogger()
root.setLevel(LOG_LEVEL)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)

logging.getLogger("didcomm").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

from didcomm_messaging import quickstart

RELAY_DID = 'did:web:dev.cloudmediator.indiciotech.io'

from typing import (
    Optional,
    Dict,
    List,
    Any,
    Union,
    Callable,
    Awaitable,
    Tuple,
)
import aiohttp
import json
import logging
import uuid

from did_peer_2 import KeySpec, generate
from pydid.did import DID

from aries_askar import Key, KeyAlg
from didcomm_messaging import DIDCommMessaging
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.multiformats import multibase, multicodec
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.resolver.web import DIDWeb
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.routing import RoutingService

JSON_OBJ = Dict[str, Any]
Attachment = JSON_OBJ
JSON_VALUE = Union[None, str, int, bool, float, JSON_OBJ, List[Any]]
def generate_did() -> Tuple[DID, Tuple[Key, Key]]:
    """Use Askar to generate encryption/verification keys, then return a DID from both."""

    verkey = Key.generate(KeyAlg.ED25519)
    xkey = Key.generate(KeyAlg.X25519)
    did = generate(
        [
            KeySpec.verification(
                multibase.encode(
                    multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                    "base58btc",
                )
            ),
            KeySpec.key_agreement(
                multibase.encode(
                    multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                )
            ),
        ],
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://192.168.70.16:8000/post",
                    "accept": ["didcomm/v2"],
                    "routingKeys": [],
                },
            }
        ],
    )
    return did, (verkey, xkey)

async def main():
    did, secrets = generate_did()
    DMP = await quickstart.setup_default(did, secrets)
    relayed_did = did
    #relayed_did = await quickstart.setup_relay(DMP, did, RELAY_DID, *secrets) or did
    await asyncio.sleep(2)
    logger.info("our did: %s" % did)
    await asyncio.sleep(8)
    #logger.info("our relayed did: %s" % relayed_did)

    logger.info("retrieving agent did")
    target_did = ""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f'{os.environ.get("CONTROLLER")}/wallet/did/create',
            json={"method": "did:peer:2"},
        ) as resp:
            target_did = (await resp.json()).get("result", {}).get("did", "")
    logger.info("agent did: %s" % target_did)
    if not target_did.startswith("did:"):
        raise Exception("Failed to retrieve target did")

    logger.info("Preparing to send message to ACA-Py Agent")
    await asyncio.sleep(2)

    message = {
        "type": "https://didcomm.org/basicmessage/2.0/message",
        # "id": str(uuid.uuid4()),
        "body": {"content": "Hello World!"},
        "frm": relayed_did,
        "lang": "en",
        "to": [target_did],
    }
    try:
        await quickstart.send_http_message(DMP, did, message, target=target_did)
    except Exception as e:
        logger.exception(e)
    #await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)
    #await asyncio.sleep(1)
    async def print_msg(msg):
        print("Received Message: ", msg["body"])
    await asyncio.sleep(5)
    if relayed_did != did:
        try:
            await quickstart.fetch_relayed_messages(DMP, did, RELAY_DID, print_msg)
        except Exception as e:
            logger.exception(e)
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f'{os.environ.get("CONTROLLER")}/shutdown',
        ) as resp:
            logger.info(await resp.text())

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
