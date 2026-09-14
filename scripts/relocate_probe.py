import asyncio, json, secrets, time
from pathlib import Path
from chimera.route_state import write_route_state, read_route_state
from chimera.range_client import HttpRangeClient, RangeOperation
from chimera.schemas import Route

RUNTIME = Path("range/runtime")
BASE = "http://127.0.0.1:18080"

async def read_configs(client):
    out = {}
    for route in Route:
        r = await client.request(route, RangeOperation.CONFIG, None)
        out[route.value] = (r.status_code, r.payload.get("canary"))
    return out

async def main():
    tokens = {r: secrets.token_urlsafe(24) for r in Route}
    c1 = secrets.token_urlsafe(24); c2 = secrets.token_urlsafe(24)
    client = HttpRangeClient(BASE)
    try:
        print("step 1: canary on api")
        write_route_state(RUNTIME, Route.API, token=tokens[Route.API], canary=c1)
        write_route_state(RUNTIME, Route.INTERNAL, token=tokens[Route.INTERNAL], canary=None)
        print("  host files:", {r.value: read_route_state(RUNTIME / r.value / "route.json").canary is not None for r in Route})
        got = await read_configs(client)
        print("  service sees canary:", {k: (v[0], v[1] == c1 if v[1] else None) for k, v in got.items()})
        print("step 2: relocate to internal")
        write_route_state(RUNTIME, Route.API, token=tokens[Route.API], canary=None)
        write_route_state(RUNTIME, Route.INTERNAL, token=tokens[Route.INTERNAL], canary=c2)
        print("  host files:", {r.value: read_route_state(RUNTIME / r.value / "route.json").canary is not None for r in Route})
        for attempt in range(4):
            got = await read_configs(client)
            print(f"  attempt {attempt} service sees:", {k: (v[0], 'c2' if v[1] == c2 else ('c1' if v[1] == c1 else v[1])) for k, v in got.items()})
            await asyncio.sleep(0.5)
        print("step 3: container view of files")
    finally:
        await client.aclose()

asyncio.run(main())
