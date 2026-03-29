import asyncio
import itertools
import json
import secrets
import websockets
import time

URI="wss://ris-live.ripe.net/v1/ws/?client=bgp-hijack-dev"

SUBSCRIBE={
    "type":"ris_subscribe",
    "data" : {"type": "UPDATE"}
}

async def stream():
    while True:
        async with websockets.connect(URI) as ws:
            await ws.send(json.dumps(SUBSCRIBE))
            print("connected... \n")
            async for message in ws:
                try:
                    data=json.loads(message)
                    msg=data.get("data",{})
                    announcements=msg.get("announcements",[])
                    peer=msg.get("peer","?")
                    withdrawals = msg.get("withdrawals", [])
                    path = msg.get("path", [])
                    
                    event={
                        "announcements":announcements,
                        "peer":peer,
                        "withdrawals":withdrawals,
                        "path":path,
                    }
                except Exception as e:
                    continue
                yield event


