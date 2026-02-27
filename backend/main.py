from fastapi import FastAPI
import httpx
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

app = FastAPI(title="ThreatView SOC Console")

VT_API = os.getenv("VT_API")
ABUSE_API = os.getenv("ABUSE_API")
OTX_API = os.getenv("OTX_API")
SHODAN_API = os.getenv("SHODAN_API")

@app.get("/")
def root():
    return {"status": "ThreatView Backend Running"}

def calculate_threat_score(results):

    score = 0
    reasons = []

    try:
        vt = results.get("virustotal", {})
        malicious = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)

        if malicious > 0:
            score += malicious * 2
            reasons.append(f"VirusTotal detections: {malicious}")

    except:
        pass

    try:
        abuse = results.get("abuseipdb", {})
        abuse_score = abuse.get("data", {}).get("abuseConfidenceScore", 0)

        if abuse_score > 0:
            score += abuse_score / 10
            reasons.append(f"AbuseIPDB score: {abuse_score}")

    except:
        pass

    verdict = "CLEAN"

    if score >= 15:
        verdict = "MALICIOUS"
    elif score >= 5:
        verdict = "SUSPICIOUS"

    return {
        "score": round(score, 2),
        "verdict": verdict,
        "reasons": reasons
    }

@app.get("/lookup/{ioc}")
async def lookup_ioc(ioc: str):

    results = {}

    async with httpx.AsyncClient(timeout=30) as client:

        if VT_API:
            try:
                vt = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                    headers={"x-apikey": VT_API}
                )
                results["virustotal"] = vt.json()
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        else:
            results["virustotal"] = {"status": "API key not configured"}

        if ABUSE_API:
            try:
                abuse = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSE_API},
                    params={"ipAddress": ioc}
                )
                results["abuseipdb"] = abuse.json()
            except Exception as e:
                results["abuseipdb"] = {"error": str(e)}
        else:
            results["abuseipdb"] = {"status": "API key not configured"}

        if OTX_API:
            try:
                otx = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
                    headers={"X-OTX-API-KEY": OTX_API}
                )
                results["otx"] = otx.json()
            except Exception as e:
                results["otx"] = {"error": str(e)}
        else:
            results["otx"] = {"status": "API key not configured"}

        if SHODAN_API:
            try:
                shodan = await client.get(
                    f"https://api.shodan.io/shodan/host/{ioc}",
                    params={"key": SHODAN_API}
                )
                results["shodan"] = shodan.json()
            except Exception as e:
                results["shodan"] = {"error": str(e)}
        else:
            results["shodan"] = {"status": "API key not configured"}

    threat_score = calculate_threat_score(results)

    return {
        "ioc": ioc,
        "threat_score": threat_score,
        "enrichment": results
    }
