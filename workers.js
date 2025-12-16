export default {
  async fetch(request, env, ctx) {
    // 1. IDENTIFY THE CLIENT
    // If testing in browser, IP might be hidden, so we fallback to a test IP
    const clientIP = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const userAgent = request.headers.get("User-Agent") || "";
    const method = request.method;
    const url = new URL(request.url);

    // 2. INITIALIZE SCORE (Start at 0)
    let currentScore = 0;
    let riskReason = [];

    // --- SIGNAL DETECTION LOGIC ---

    // Signal A: Missing or Suspicious User-Agent (+20 points)
    // "curl" is often used by bots/scrapers
    if (!userAgent || userAgent.length < 5 || userAgent.toLowerCase().includes("curl")) {
      currentScore += 20;
      riskReason.push("Bad-UA");
    }

    // Signal B: Non-Standard HTTP Methods (+15 points)
    // Most browsers only use GET or POST
    const allowedMethods = ["GET", "POST", "HEAD"];
    if (!allowedMethods.includes(method)) {
      currentScore += 15;
      riskReason.push("Bad-Method");
    }

    // Signal C: Suspicious Query Strings (+30 points)
    // Looking for SQL Injection or Path Traversal patterns
    const query = url.search.toUpperCase();
    if (query.includes("UNION") || query.includes("../") || query.includes("SELECT")) {
      currentScore += 30;
      riskReason.push("Attack-Signature");
    }

    // 3. CHECK HISTORY (THE STATEFUL PART)
    // Read previous score from KV. Default to 0 if new.
    let historicalScore = await env.IP_RISK.get(clientIP);
    historicalScore = historicalScore ? parseInt(historicalScore) : 0;

    // 4. CALCULATE TOTAL RISK
    let totalRisk = historicalScore + currentScore;

    // 5. UPDATE MEMORY (Write back to KV)
    // Only write if there is a new risk score to save operations/money
    if (currentScore > 0) {
      // Remember bad behavior for 24 hours (86400 seconds)
      await env.IP_RISK.put(clientIP, totalRisk.toString(), { expirationTtl: 86400 });
    }

    // 6. ENFORCEMENT DECISION
    // Threshold: If Score >= 50, BLOCK.
    if (totalRisk >= 50) {
      return new Response(`BLOCKED.\n\nReputation Score: ${totalRisk}\nReasons: ${riskReason.join(", ")}\nAction: IP Temporarily Banned`, {
        status: 403,
        headers: { "X-Reputation-Score": totalRisk.toString() }
      });
    }

    // 7. PASS TRAFFIC (Simulation)
    // In a real app, this would fetch the origin website. 
    // For this demo, we return a success message so you can see the logic working.
    return new Response(`ALLOWED.\n\nYour IP: ${clientIP}\nCurrent Request Risk: ${currentScore}\nTotal Reputation Score: ${totalRisk}\nStatus: Clean`, {
      status: 200,
      headers: { "X-Reputation-Score": totalRisk.toString() }
    });
  }
};
