import asyncio
import aiohttp
import uuid
import os
import sys
import logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
root = logging.getLogger()
root.setLevel(LOG_LEVEL)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)

logging.getLogger("didcomm").setLevel(logging.WARN)
logger = logging.getLogger(__name__)

from didcomm_messaging import quickstart

RELAY_DID = 'did:web:dev.cloudmediator.indiciotech.io'

async def main():
    did, secrets = quickstart.generate_did()
    DMP = await quickstart.setup_default(did, secrets)
    #relayed_did = await quickstart.setup_relay(DMP, did, RELAY_DID, *secrets) or did
    logger.info("our did: %s" % did)
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
        "frm": did,
        "lang": "en",
        "to": [target_did],
    }
    await quickstart.send_http_message(DMP, did, message, target=target_did)
    #await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)
    #await asyncio.sleep(1)
    async def print_msg(msg):
        print("Received Message: ", msg["body"])
    #await quickstart.fetch_relayed_messages(DMP, did, RELAY_DID, print_msg)

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
