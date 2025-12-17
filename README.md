# Cloudflare Workers: Stateful Reputation Engine

A serverless security system that tracks client behavior across requests to assign a cumulative risk score.

## Components:
- Uses Cloudflare Workers KV to store risk scores per IP address (24h TTL).
- JavaScript parser inspects HTTP Headers and Query Strings for attack signatures.
- Automatically blocks traffic when `Risk Score > 50`.

## How it works:
1. The Worker analyzes every incoming request on this link: `https://reputation-engine.ryan-benson-lab.workers.dev`
2. It assigns points for suspicious behavior; some actions have different points given.
3. It remembers score from previous sessions, and retrieves the IP's history from KV if suspicious action happend again, and adds the new points.
4. If user user made too much suspicious actions and hitted 50, the user is getting blocked.

## Live Demo
[https://reputation-engine.ryan-benson-lab.workers.dev]
