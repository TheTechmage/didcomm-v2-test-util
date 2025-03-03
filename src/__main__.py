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

logging.getLogger("didcomm").setLevel(logging.INFO)
logger = logging.getLogger(__name__)

from didcomm_messaging import quickstart

RELAY_DID = 'did:web:dev.cloudmediator.indiciotech.io'
PI_DID = 'did:peer:2.Vz6MkpmLbME7y9Qpa1ioCAyZ7YhLckUfbTGztfmVnGjAsGUGY.Ez6LSc14pA4VMT2MsrARgGFkLmshynDgmAq5wwui2swKzXxVT.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFN0a1pnMTRvRzVMQ3hqYTNSaG90V0I3bTk0YWZFUjRFaUJMaFlwVVNva2J5Ui5WejZNa2dTWUJNNjNpSE5laVQyVlNRdTdiYnRYaEdZQ1FyUEo4dUVHdXJiZkdiYmdFLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW1oMGRIQnpPaTh2ZFhNdFpXRnpkQzV3ZFdKc2FXTXViV1ZrYVdGMGIzSXVhVzVrYVdOcGIzUmxZMmd1YVc4dmJXVnpjMkZuWlNJc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxOS5TZXlKMElqb2laRzBpTENKeklqcDdJblZ5YVNJNkluZHpjem92TDNkekxuVnpMV1ZoYzNRdWNIVmliR2xqTG0xbFpHbGhkRzl5TG1sdVpHbGphVzkwWldOb0xtbHZMM2R6SWl3aVlTSTZXeUprYVdSamIyMXRMM1l5SWl3aVpHbGtZMjl0YlM5aGFYQXlPMlZ1ZGoxeVptTXhPU0pkZlgwLlNleUp6SWpvZ0ltaDBkSEJ6T2k4dmRYTXRaV0Z6ZEM1d2RXSnNhV011YldWa2FXRjBiM0l1YVc1a2FXTnBiM1JsWTJndWFXOHZiV1Z6YzJGblpTSXNJQ0poSWpvZ1d5SmthV1JqYjIxdEwyRnBjREVpTENKa2FXUmpiMjF0TDJGcGNESTdaVzUyUFhKbVl6RTVJbDBzSUNKeVpXTnBjR2xsYm5STFpYbHpJam9nV3lJamEyVjVMVElpWFN3Z0luUWlPaUFpWkdsa0xXTnZiVzExYm1sallYUnBiMjRpZlEuU2V5SnpJam9nSW5kemN6b3ZMM2R6TG5WekxXVmhjM1F1Y0hWaWJHbGpMbTFsWkdsaGRHOXlMbWx1WkdsamFXOTBaV05vTG1sdkwzZHpJaXdnSW1FaU9pQmJJbVJwWkdOdmJXMHZZV2x3TVNJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFN3Z0luSmxZMmx3YVdWdWRFdGxlWE1pT2lCYklpTnJaWGt0TWlKZExDQWlkQ0k2SUNKa2FXUXRZMjl0YlhWdWFXTmhkR2x2YmlKOSIsImEiOlsiZGlkY29tbS92MiJdfX0'

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
            json={"method": "did:peer:4"},
        ) as resp:
            target_did = (await resp.json()).get("result", {}).get("did", "")
    logger.info("agent did: %s" % target_did)
    async with aiohttp.ClientSession() as session:
        async with session.post(
            'http://172.24.1.11:9494/post',
            data=target_did,
        ) as resp:
            logger.info("Posted data, received: %s", await resp.read())

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
        "from": relayed_did,
        "lang": "en",
        "to": [target_did],
    }
    try:
        await quickstart.send_http_message(DMP, did, message, target=target_did)
    except Exception as e:
        logger.exception(e)
    await asyncio.sleep(2)
    contact_id = None
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f'{os.environ.get("CONTROLLER")}/connections-v2',
        ) as resp:
            r = await resp.json()
            logger.info(r)
            contact_id = r["results"][0]["pairwise_id"]
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f'{os.environ.get("CONTROLLER")}/connections-v2/{contact_id}',
        ) as resp:
            logger.info(await resp.text())
    async with aiohttp.ClientSession() as session:
        async with session.delete(
            f'{os.environ.get("CONTROLLER")}/connections-v2/{contact_id}',
        ) as resp:
            logger.info(await resp.text())
    async with aiohttp.ClientSession() as session:
        import random
        nametag = "ACA-Py" + str(random.randint(1, 10))
        async with session.post(
            f'{os.environ.get("CONTROLLER")}/name-tag/set-name',
            json={
                "to_did": PI_DID,
                "content": nametag,
            },
        ) as resp:
            print((await resp.json()).get("result", {}).get("did", ""))
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
    await asyncio.sleep(10)
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f'{os.environ.get("CONTROLLER")}/connections-v2',
        ) as resp:
            logger.info(await resp.text())
    #async with aiohttp.ClientSession() as session:
    #    async with session.get(
    #        f'{os.environ.get("CONTROLLER")}/shutdown',
    #    ) as resp:
    #        logger.info(await resp.text())
    logger.info("agent did: %s" % target_did)
    logger.info("Name Tag: %s" % nametag)
    #async with aiohttp.ClientSession() as session:
    #    async with session.post(
    #        'http://172.24.1.11:8084/7362c3f4-15ec-4964-88fd-4bdf78491f2e',
    #        data=target_did,
    #    ) as resp:
    #        logger.info("Posted data, received: %s", await resp.read())

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
