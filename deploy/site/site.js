// The one live thing on the page: the latest block, read from the public RPC.
// If it cannot be reached the page simply says so; nothing else depends on it.
(async function () {
  const $ = (id) => document.getElementById(id);
  const heroDot = $("hero-dot"), netDot = $("net-dot");
  const setLive = (live) => {
    for (const dot of [heroDot, netDot]) dot.classList.toggle("good", live);
    $("hero-line").textContent = live ? "Alpha testnet is live" : "Alpha testnet";
    $("net-text").textContent = live ? "Testnet live" : "Alpha testnet";
  };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    const res = await fetch("https://rpc.thrylos.org/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "status", params: {} }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const data = await res.json();
    const height = data && data.result && data.result.latest && data.result.latest.height;
    if (typeof height !== "number" || data.result.halted) throw new Error("not producing blocks");
    $("height").textContent = height.toLocaleString("en-US");
    $("height-note").textContent = "Blocks about once a second";
    setLive(true);
  } catch {
    $("height").textContent = "—";
    $("height-note").textContent = "Could not reach the network right now";
    setLive(false);
  }
})();
