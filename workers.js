export default {
  async fetch(request, env) {

    const ip = request.headers.get("CF-Connecting-IP");
    const url = new URL(request.url);

    let newPoints = 0;


    const ua = request.headers.get("User-Agent") || "";
    if (ua.includes("curl") || ua.length < 5) newPoints += 20;

    const cookies = request.headers.get("Cookie");
    if (!cookies) {
        newPoints += 15; 
    }

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

    let response;
    
    if (totalScore >= 50) {
      response = new Response(`BLOCKED. Reputation Score: ${totalScore}`, { status: 403 });
    } else {
      response = new Response(`PASSED. Current Score: ${totalScore}`, { status: 200 });
    }

    if (!cookies) {
      response.headers.set("Set-Cookie", "verified=true;");
    }
    
    return response;
  }
};
