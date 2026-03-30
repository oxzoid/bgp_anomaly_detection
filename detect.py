import sqlite3
import time
import asyncio
import json
from ingest import stream
import aiohttp
from fastapi import FastAPI, WebSocket, WebSocketDisconnect,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import ijson

@asynccontextmanager
async def lifespan(app: FastAPI):
    task1 = asyncio.create_task(store())
    task2 = asyncio.create_task(download_rpki())
    task3 = asyncio.create_task(clear())
    yield
    task1.cancel()
    task2.cancel()
    task3.cancel()

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://oxzoid.github.io"],
    # allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

con = sqlite3.connect("bgp.db", check_same_thread=False)
cur = con.cursor()

cur.execute("CREATE TABLE IF NOT EXISTS bgp_prefix_asn(created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ,prefix VARCHAR PRIMARY KEY,authorized_asn INTEGER,hijacking_asn INTEGER)")
cur.execute("CREATE TABLE IF NOT EXISTS roas(prefix VARCHAR,asn INTEGER)")
ANOMALY=set()
RPKI={}

async def clear():
    c_cur = con.cursor()
    while True:
        try:
            delete_query = "DELETE FROM bgp_prefix_asn WHERE created_at <= datetime('now', '-2 minutes')"
            await asyncio.to_thread(c_cur.execute,delete_query)
            await asyncio.sleep(120)
        except Exception as e:
            print(e)
            continue


@app.get("/data")
@limiter.limit("30/minute")
async def send(request: Request):
    ws_cur = con.cursor()
    await asyncio.to_thread(ws_cur.execute,"Select * from bgp_prefix_asn ORDER BY created_at DESC LIMIT 50")
    rows=await asyncio.to_thread(ws_cur.fetchall)
    dict_data = [{"created_at": row[0], "prefix": row[1], "authorized_asn": row[2], "hijacking_asn": row[3]} for row in rows]            
    return dict_data
    
async def store():
    s_cur = con.cursor()
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
                        await asyncio.to_thread(s_cur.execute,"Select asn from roas where prefix=?",(prefix,))
                        authorized_asn = await asyncio.to_thread(s_cur.fetchone)
                        if authorized_asn is None:
                            continue
                        elif origin_asn == authorized_asn[0]:
                            continue
                        else:
                            if (prefix,origin_asn) not in ANOMALY:
                                ANOMALY.add((prefix,origin_asn))
                                await asyncio.to_thread(s_cur.execute,"INSERT INTO bgp_prefix_asn VALUES(datetime('now'),?,?,?)",(prefix,authorized_asn[0],origin_asn))
                                await asyncio.to_thread(con.commit)
                                # print(f"anomaly detected,prefix {prefix} announced by ASN {authorized_asn} now being announced by {origin_asn}")
                            else:
                                continue
        except Exception as e:
            continue
async def download_rpki():
    r_cur = con.cursor()
    global RPKI
    while True:
        await asyncio.to_thread(r_cur.execute,"DELETE FROM roas")
        await asyncio.to_thread(con.commit)
        async with aiohttp.ClientSession() as session:
            async with session.get('https://rpki.cloudflare.com/rpki.json') as resp:
                async for roa in ijson.items_async(resp.content, 'roas.item'):
                    if ':' not in roa['prefix']:
                        await asyncio.to_thread(r_cur.execute, "INSERT OR REPLACE INTO roas VALUES(?,?)", (roa['prefix'], roa['asn']))
            await asyncio.to_thread(con.commit)
        await asyncio.sleep(1200)
        
