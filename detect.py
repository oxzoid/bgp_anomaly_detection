import sqlite3
import time
import asyncio
import json
from ingest import stream

con = sqlite3.connect("bgp.db")
cur = con.cursor()

cur.execute("CREATE TABLE IF NOT EXISTS bgp_prefix_asn(prefix VARCHAR PRIMARY KEY,asn INTEGER)")


async def store():
    async for event in stream():
        announcements=event.get("announcements",[])
        for a in announcements:
            for prefix in a.get("prefixes", []):
                path=event.get("path",[])
                origin_asn=path[-1] if path else None
                if isinstance(origin_asn, list):
                        continue
                cur.execute("SELECT asn FROM bgp_prefix_asn WHERE prefix = ?", (prefix,))
                row=cur.fetchone()
                # print(path)
                if row is None:
                    # print(f"{prefix},{origin_asn}")
                    cur.execute("INSERT INTO bgp_prefix_asn VALUES(:prefix, :asn)", {"prefix": prefix, "asn": origin_asn})
                    con.commit()
                else:
                    if origin_asn != row[0]:
                        print(f"anomaly detected,prefix {prefix} announced by ASN {row[0]} now being announced by {origin_asn}")
                    else:
                        continue

if __name__=="__main__":
    asyncio.run(store())