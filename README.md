# Cloudflare Workers: Stateful Reputation Engine

A serverless security system that tracks client behavior across requests to assign a cumulative risk score.

## Components:
- Uses Cloudflare Workers KV to store risk scores per IP address (24h TTL).
- JavaScript parser inspects HTTP Headers and Query Strings for attack signatures.
- Automatically blocks traffic when `Risk Score > 50`.

## How it works:
1. The Worker analyzes every incoming request on this link: `https://reputation-engine.ryan-benson-lab.workers.dev`
2. It assigns weighted risk points for suspicious behavior.
3. It retrieves the IP's history from KV and adds new points to the existing score if the user continues a suspicious activity.
4. If the cumulative risk score hits the threshold of 50, the user is automatically blocked.

## Live Demo
[https://reputation-engine.ryan-benson-lab.workers.dev]
