import sqlite3
import time
import asyncio
import json
from ingest import stream

con = sqlite3.connect("bgp.db", check_same_thread=False)
cur = con.cursor()

cur.execute("CREATE TABLE IF NOT EXISTS bgp_prefix_asn(prefix VARCHAR PRIMARY KEY,asn INTEGER)")
CACHE={}
TEMP=[]
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
                        if prefix not in CACHE:
                            await asyncio.to_thread(cur.execute,"SELECT asn FROM bgp_prefix_asn WHERE prefix = ?", (prefix,))
                            row=await asyncio.to_thread(cur.fetchone)
                        else:
                            row=CACHE[prefix]
                        # print(path)
                        if row is None:
                            # print(f"{prefix},{origin_asn}")
                            CACHE[prefix]=(origin_asn,)
                            if(len(TEMP)<100):
                                TEMP.append((prefix,origin_asn))
                            else:                                    
                                await asyncio.to_thread(cur.executemany,"INSERT INTO bgp_prefix_asn VALUES(?,?)",TEMP)
                                await asyncio.to_thread(con.commit)
                                TEMP.clear()
                        else:
                            if origin_asn != row[0]:
                                print(f"anomaly detected,prefix {prefix} announced by ASN {row[0]} now being announced by {origin_asn}")
                            else:
                                continue
        except Exception as e:
            continue

if __name__=="__main__":
    asyncio.run(store())