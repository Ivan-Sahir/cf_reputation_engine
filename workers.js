export default {
  async fetch(request, env) {

    const ip = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const url = new URL(request.url);

    let newPoints = 0;


    const ua = request.headers.get("User-Agent") || "";
    if (ua.includes("curl") || ua.length < 5) newPoints += 20;


    const query = url.search.toUpperCase();
    if (query.includes("UNION") || query.includes("SELECT") || query.includes("../")) {
      newPoints += 30;
    }

    const protocol = url.protocol;
    if (protocol === "http:"){
      newPoints += 15
    }

    const oldScore = parseInt(await env.IP_RISK.get(ip)) || 0;
    const totalScore = oldScore + newPoints;

    if (newPoints > 0) {
      await env.IP_RISK.put(ip, totalScore.toString(), { expirationTtl: 86400 });
    }

    if (totalScore >= 50) {
      return new Response(`BLOCKED. Reputation Score: ${totalScore}`, { status: 403 });
    }

    return new Response(`PASSED. Current Score: ${totalScore}`, { status: 200 });
  }
};
