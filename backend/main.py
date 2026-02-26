from fastapi import FastAPI
import httpx
import os

app = FastAPI(title="ThreatView SOC Console")

VT_API = os.getenv("VT_API")
ABUSE_API = os.getenv("ABUSE_API")
OTX_API = os.getenv("OTX_API")
GREYNOISE_API = os.getenv("GREYNOISE_API")
SHODAN_API = os.getenv("SHODAN_API")

@app.get("/")
def root():
    return {"status": "ThreatView Backend Running"}

@app.get("/lookup/{ioc}")
async def lookup_ioc(ioc: str):

    results = {}

    async with httpx.AsyncClient(timeout=30) as client:

        try:
            vt = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                headers={"x-apikey": VT_API}
            )
            results["virustotal"] = vt.json()
        except:
            results["virustotal"] = "error"

        try:
            abuse = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_API},
                params={"ipAddress": ioc}
            )
            results["abuseipdb"] = abuse.json()
        except:
            results["abuseipdb"] = "error"

        try:
            otx = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
                headers={"X-OTX-API-KEY": OTX_API}
            )
            results["otx"] = otx.json()
        except:
            results["otx"] = "error"

        try:
            gn = await client.get(
                f"https://api.greynoise.io/v3/community/{ioc}",
                headers={"key": GREYNOISE_API}
            )
            results["greynoise"] = gn.json()
        except:
            results["greynoise"] = "error"

        try:
            shodan = await client.get(
                f"https://api.shodan.io/shodan/host/{ioc}",
                params={"key": SHODAN_API}
            )
            results["shodan"] = shodan.json()
        except:
            results["shodan"] = "error"

    return results
