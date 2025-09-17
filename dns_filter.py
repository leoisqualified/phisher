import requests
import logging
from dnslib import DNSRecord, QTYPE, RR, A, server

API_URL = "http://localhost:5000/predict"
UPSTREAM_DNS = "1.1.1.1"  # Cloudflare fallback


class PhishingDNSHandler:
    def resolve(self, request, handler):
        qname = str(request.q.qname).strip(".")
        url = f"http://{qname}"

        try:
            resp = requests.post(
                API_URL,
                headers={"Content-Type": "application/json"},
                json={"url": url},
                timeout=2,
            )
            verdict = resp.json().get("verdict", "safe")
        except Exception as e:
            logging.error(f"DNS filter API call failed for {qname}: {e}")
            verdict = "safe"

        reply = request.reply()
        if verdict == "phishing":
            # Block by returning 0.0.0.0
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
        else:
            # Forward safe domains to upstream resolver
            upstream_reply = DNSRecord.parse(request.send(UPSTREAM_DNS, 53))
            reply = upstream_reply

        return reply


if __name__ == "__main__":
    resolver = PhishingDNSHandler()
    dns_server = server.DNSServer(resolver, port=53, address="0.0.0.0")
    print("Phishing DNS filter running on port 53...")
    dns_server.start()
