export default {
  async fetch(request, env) {
    // GET USER DATA
    const ip = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const url = new URL(request.url);
    
    // CALCULATE NEW SCORE (Start at 0)
    let newPoints = 0;

    // Block Curl and empty User Agents 
    const ua = request.headers.get("User-Agent") || "";
    if (ua.includes("curl") || ua.length < 5) newPoints += 20;

    // Detect SQL Injection in the URL
    // words like "UNION" or "SELECT" in the query
    const query = url.search.toUpperCase();
    if (query.includes("UNION") || query.includes("SELECT") || query.includes("../")) {
      newPoints += 30;
    }

    // CHECK HISTORY (Fetch from KV Database)
    // get the old score. If it doesn't exist, treat it as 0.
    const oldScore = parseInt(await env.IP_RISK.get(ip)) || 0;
    const totalScore = oldScore + newPoints;

    // UPDATE DATABASE
    // If user made a bad move again, save the new total (Remember for 24 hours)
    if (newPoints > 0) {
      await env.IP_RISK.put(ip, totalScore.toString(), { expirationTtl: 86400 });
    }

    // DECISION (Block oif more than 50)
    if (totalScore >= 50) {
      return new Response(`BLOCKED. Reputation Score: ${totalScore}`, { status: 403 });
    }

    return new Response(`PASSED. Current Score: ${totalScore}`, { status: 200 });
  }
};
