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

        # VirusTotal
        if VT_API:
            try:
                vt = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                    headers={"x-apikey": VT_API}
                )
                results["virustotal"] = vt.json()
            except Exception as e:
                results["virustotal"] = str(e)
        else:
            results["virustotal"] = "API key not configured"

        # AbuseIPDB
        if ABUSE_API:
            try:
                abuse = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSE_API},
                    params={"ipAddress": ioc}
                )
                results["abuseipdb"] = abuse.json()
            except Exception as e:
                results["abuseipdb"] = str(e)
        else:
            results["abuseipdb"] = "API key not configured"

        # AlienVault OTX
        if OTX_API:
            try:
                otx = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
                    headers={"X-OTX-API-KEY": OTX_API}
                )
                results["otx"] = otx.json()
            except Exception as e:
                results["otx"] = str(e)
        else:
            results["otx"] = "API key not configured"

        # GreyNoise (optional)
        if GREYNOISE_API:
            try:
                gn = await client.get(
                    f"https://api.greynoise.io/v3/community/{ioc}",
                    headers={"key": GREYNOISE_API}
                )
                results["greynoise"] = gn.json()
            except Exception as e:
                results["greynoise"] = str(e)
        else:
            results["greynoise"] = "Not configured"

        # Shodan
        if SHODAN_API:
            try:
                shodan = await client.get(
                    f"https://api.shodan.io/shodan/host/{ioc}",
                    params={"key": SHODAN_API}
                )
                results["shodan"] = shodan.json()
            except Exception as e:
                results["shodan"] = str(e)
        else:
            results["shodan"] = "API key not configured"

    return results