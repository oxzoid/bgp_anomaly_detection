import sqlite3
import time
import asyncio
import json
from ingest import stream
import aiohttp
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    task1 = asyncio.create_task(store())
    task2 = asyncio.create_task(download_rpki())
    task3 = asyncio.create_task(clear())
    yield
    task1.cancel()
    task2.cancel()
    task3.cancel()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

con = sqlite3.connect("bgp.db", check_same_thread=False)
cur = con.cursor()

cur.execute("CREATE TABLE IF NOT EXISTS bgp_prefix_asn(created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ,prefix VARCHAR PRIMARY KEY,authorized_asn INTEGER,hijacking_asn INTEGER)")
ANOMALY=set()
RPKI={}

async def clear():
    while True:
        try:
            delete_query = "DELETE FROM bgp_prefix_asn WHERE created_at <= datetime('now', '-1 minutes')"
            await asyncio.to_thread(cur.execute,delete_query)
            await asyncio.sleep(60)
        except Exception as e:
            print(e)
            continue


@app.get("/data")
async def send():
    ws_cur = con.cursor()
    await asyncio.to_thread(ws_cur.execute,"Select * from bgp_prefix_asn ORDER BY created_at DESC LIMIT 50")
    rows=await asyncio.to_thread(ws_cur.fetchall)
    dict_data = [{"created_at": row[0], "prefix": row[1], "authorized_asn": row[2], "hijacking_asn": row[3]} for row in rows]            
    return dict_data
    
async def store():
    while True:
        try:       
            async for event in stream():
                announcements=event.get("announcements",[])
                for a in announcements:
                    for prefix in a.get("prefixes", []):
                        path=event.get("path",[])
                        origin_asn=path[-1] if path else None
                        if isinstance(origin_asn, list):
                                continue
                        authorized_asn = RPKI.get(prefix)
                        if authorized_asn is None:
                            continue
                        elif origin_asn == authorized_asn:
                            continue
                        else:
                            if (prefix,origin_asn) not in ANOMALY:
                                ANOMALY.add((prefix,origin_asn))
                                await asyncio.to_thread(cur.execute,"INSERT INTO bgp_prefix_asn VALUES(datetime('now'),?,?,?)",(prefix,authorized_asn,origin_asn))
                                await asyncio.to_thread(con.commit)
                                # print(f"anomaly detected,prefix {prefix} announced by ASN {authorized_asn} now being announced by {origin_asn}")
                            else:
                                continue
        except Exception as e:
            continue
async def download_rpki():
    global RPKI
    while True:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://rpki.cloudflare.com/rpki.json') as resp:    
                temp1=json.loads(await resp.text())
                RPKI={roa['prefix']: roa['asn'] for roa in temp1['roas']}
        await asyncio.sleep(1200)
