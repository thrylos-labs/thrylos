"use strict";

const REFRESH_MS = 2_000;
const BLOCKS_TO_SHOW = 5;
const HISTORY_BLOCKS = 12;

const byId = (id) => document.getElementById(id);
const state = { info: null, status: null, health: null, blocks: [], refreshing: false };

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = value;
}

function short(value, start = 9, end = 7) {
  if (typeof value !== "string" || value.length <= start + end + 1) return value || "—";
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

function age(timestampMs) {
  if (!Number.isFinite(timestampMs)) return "unknown age";
  const seconds = Math.max(0, Math.floor((Date.now() - timestampMs) / 1_000));
  if (seconds < 2) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ago`;
}

function make(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

async function request(path, options) {
  const response = await fetch(path, options);
  let payload;
  try {
    payload = await response.json();
  } catch (_) {
    throw new Error(`Explorer backend answered HTTP ${response.status}.`);
  }
  if (!response.ok || !payload.ok) {
    const error = new Error(payload.error || `Request failed with HTTP ${response.status}.`);
    error.hint = payload.hint || "";
    throw error;
  }
  return payload.result;
}

function rpc(method, params = {}) {
  return request("/api/rpc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, params }),
  });
}

function showConnectionError(error) {
  const notice = byId("connection-notice");
  notice.hidden = false;
  setText("connection-message", error.message || String(error));
  setText("connection-hint", error.hint || "Start the local network, then refresh this page.");
  setHealthState(false, "Network unreachable");
}

function clearConnectionError() {
  byId("connection-notice").hidden = true;
}

function setHealthState(healthy, label) {
  setText("health-line", label);
  ["header-dot", "hero-dot", "footer-dot"].forEach((id) => {
    const dot = byId(id);
    dot.classList.toggle("good", healthy);
    dot.classList.toggle("bad", !healthy);
  });
}

function renderStats() {
  const status = state.status;
  if (!status) return;
  const latest = status.latest || {};
  setText("latest-height", latest.height ?? "—");
  setText("latest-age", age(latest.timestampMs));
  setText("pending-count", status.mempool ?? "—");
  const previous = state.blocks.find((block) => block.height === Number(latest.height) - 1);
  const interval = previous && Number.isFinite(previous.timestampMs) && Number.isFinite(latest.timestampMs)
    ? Math.max(0, (latest.timestampMs - previous.timestampMs) / 1_000)
    : null;
  setText("block-time", interval === null ? "—" : `~${interval.toFixed(1)}s`);

  const total = state.health?.nodeCount ?? state.info?.nodes?.length;
  setText("validator-count", total ? `${state.health?.healthy ? total : "?"} / ${total}` : "—");
  setText("validator-note", state.health?.healthy ? "All agreeing" : "See network health");
}

function blockRow(block) {
  const row = make("article", "list-row");
  const primary = make("div", "row-primary");
  const link = make("a", "row-link", `Block ${block.height}`);
  link.href = `#block-${block.height}`;
  link.addEventListener("click", (event) => {
    event.preventDefault();
    showBlock(block.height);
  });
  primary.append(link, make("div", "row-meta hash", short(block.hash)));

  const secondary = make("div", "row-secondary");
  const count = Number(block.transactionCount || 0);
  secondary.append(
    make("div", "", `${count} transaction${count === 1 ? "" : "s"}`),
    make("div", "row-meta hash", `state ${short(block.stateRoot, 7, 5)}`),
  );
  row.append(primary, secondary, make("div", "age", age(block.timestampMs)));
  return row;
}

function transactionRow(transaction, block) {
  const row = make("article", "list-row");
  const primary = make("div", "row-primary");
  const link = make("a", "row-link hash", short(transaction.hash));
  link.href = `#tx-${transaction.hash}`;
  link.addEventListener("click", (event) => {
    event.preventDefault();
    showTransaction(transaction.hash);
  });
  primary.append(link, make("div", "row-meta", `Sequence ${transaction.sequenceNumber ?? "—"}`));

  const secondary = make("div", "row-secondary");
  secondary.append(make("div", "", `Block ${block.height}`), make("div", "row-meta", age(block.timestampMs)));
  const status = transaction.outcome?.status || "included";
  row.append(primary, secondary, make("span", `status-badge ${status === "aborted" ? "aborted" : ""}`, status));
  return row;
}

function renderActivity() {
  const blocksList = byId("blocks-list");
  blocksList.replaceChildren();
  if (!state.blocks.length) {
    blocksList.append(make("p", "empty-state", "No committed blocks were returned."));
  } else {
    state.blocks.slice(0, BLOCKS_TO_SHOW).forEach((block) => blocksList.append(blockRow(block)));
  }

  const transactions = state.blocks.flatMap((block) =>
    (Array.isArray(block.transactions) ? block.transactions : []).map((transaction) => ({ transaction, block })),
  );
  const transactionsList = byId("transactions-list");
  transactionsList.replaceChildren();
  if (!transactions.length) {
    transactionsList.append(make("p", "empty-state", "No transactions in the latest blocks yet."));
  } else {
    transactions.slice(0, BLOCKS_TO_SHOW).forEach(({ transaction, block }) =>
      transactionsList.append(transactionRow(transaction, block)),
    );
  }
  setText("transactions-meta", `${transactions.length} found in ${state.blocks.length} blocks`);
}

function renderActivityError(error) {
  const message = error?.message || String(error);
  const blocksList = byId("blocks-list");
  const transactionsList = byId("transactions-list");
  blocksList.replaceChildren(make("p", "empty-state", `Recent blocks could not be loaded: ${message}`));
  transactionsList.replaceChildren(make("p", "empty-state", "Recent transactions are temporarily unavailable."));
  setText("transactions-meta", "History unavailable");
}

function nodeStateFromNote(note) {
  const match = /^node (\d+) \(RPC ([^)]+)\): height (\d+), newest block (.+)$/.exec(note);
  if (!match) return null;
  return { number: Number(match[1]), rpc: match[2], height: match[3], age: match[4] };
}

function renderHealth() {
  const health = state.health;
  if (!health) return;
  const badge = byId("health-badge");
  badge.textContent = health.healthy ? "Healthy" : health.verdict;
  badge.classList.toggle("good", health.healthy);
  badge.classList.toggle("bad", !health.healthy);
  setHealthState(
    health.healthy,
    health.healthy
      ? `Network healthy · ${health.nodeCount} of ${health.nodeCount} validators agreeing`
      : health.verdict,
  );

  const notes = Array.isArray(health.notes) ? health.notes.map(nodeStateFromNote).filter(Boolean) : [];
  const list = byId("node-list");
  list.replaceChildren();
  if (!notes.length) {
    list.append(make("p", "empty-state", health.nobodyAnswered ? "No validator answered." : "No node details returned."));
  } else {
    notes.forEach((node) => {
      const row = make("article", "node-row");
      const identity = make("div", "");
      identity.append(make("strong", "", `Node ${node.number}`), make("div", "", ""));
      identity.lastChild.append(make("code", "", node.rpc));
      const nodeState = make("div", "node-state");
      nodeState.append(make("div", "", `Block ${node.height}`), make("div", "row-meta", node.age));
      row.append(identity, nodeState);
      list.append(row);
    });
  }

  const problems = byId("network-problems");
  problems.replaceChildren();
  const findings = Array.isArray(health.problems) ? health.problems : [];
  problems.hidden = findings.length === 0;
  findings.forEach((finding) => problems.append(make("p", "", `Problem: ${finding}`)));
}

function detailEntries(result) {
  const outcome = result.outcome && typeof result.outcome === "object" ? result.outcome : null;
  const preferred = [
    ["Status", result.status],
    ["Outcome", outcome?.status],
    ["Reason", outcome?.message],
    ["Height", result.height],
    ["Hash", result.hash],
    ["Block hash", result.blockHash],
    ["Parent hash", result.parentHash],
    ["State root", result.stateRoot],
    ["Address", result.address],
    ["Balance", formatBalance(result.balance)],
    ["Next sequence", result.nextSequenceNumber],
    ["Transactions", result.transactionCount],
    ["Timestamp", Number.isFinite(result.timestampMs) ? new Date(result.timestampMs).toLocaleString() : null],
  ];
  return preferred.filter(([, value]) => value !== null && value !== undefined);
}

function formatBalance(value) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return value;
  try {
    const units = BigInt(value);
    const base = 1_000_000_000n;
    const whole = units / base;
    const fraction = String(units % base).padStart(9, "0").replace(/0+$/, "");
    return `${whole}${fraction ? `.${fraction}` : ""} THRY`;
  } catch (_) {
    return value;
  }
}

function renderResult(type, title, result) {
  const panel = byId("search-result");
  setText("result-type", type);
  setText("result-title", title);
  setText("result-json", JSON.stringify(result, null, 2));
  const details = byId("result-details");
  details.replaceChildren();
  detailEntries(result).forEach(([label, value]) => {
    const wrapper = make("div", "");
    const term = make("dt", "", label);
    const longValue = typeof value === "string" && value.length > 24;
    const description = make("dd", longValue ? "detail-value hash" : "detail-value");
    description.append(make("span", "", String(value)));
    if (longValue) {
      const copy = make("button", "copy-button", "Copy");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(String(value));
          copy.textContent = "Copied";
          window.setTimeout(() => { copy.textContent = "Copy"; }, 1_500);
        } catch (_) {
          copy.textContent = "Select value";
        }
      });
      description.append(copy);
    }
    wrapper.append(term, description);
    details.append(wrapper);
  });
  panel.hidden = false;
  panel.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

async function showBlock(height) {
  try {
    const result = await rpc("block", { height: Number(height), full: true });
    renderResult("Block", `Block ${result.height}`, result);
  } catch (error) {
    searchError(error.message);
  }
}

async function showTransaction(hash) {
  try {
    const result = await rpc("transaction", { hash });
    renderResult("Transaction", short(hash, 14, 10), result);
  } catch (error) {
    searchError(error.message);
  }
}

async function showAccount(address) {
  try {
    const result = await rpc("account", { address });
    renderResult("Account", short(address, 15, 10), result);
  } catch (error) {
    searchError(error.message);
  }
}

function searchError(message) {
  const help = byId("search-help");
  help.textContent = message;
  help.style.color = "var(--bad)";
}

async function handleSearch(event) {
  event.preventDefault();
  const input = byId("search-input");
  const query = input.value.trim();
  byId("search-help").style.color = "";
  if (/^\d+$/.test(query)) return showBlock(query);
  if (/^thry1[0-9a-z]+$/i.test(query)) return showAccount(query);
  if (/^(0x)?[0-9a-f]{64}$/i.test(query)) return showTransaction(query.replace(/^0x/i, ""));
  searchError("That does not look like a block height, transaction hash, or Thrylos address.");
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    const status = await rpc("status");
    state.status = status;
    clearConnectionError();
    if (!state.health) {
      setHealthState(true, "Connected · checking validator agreement…");
    }
    renderStats();

    const health = await request("/api/health");
    state.health = health;
    renderStats();
    renderHealth();

    const head = Number(status.latest?.height);
    const wanted = state.blocks.length ? BLOCKS_TO_SHOW : HISTORY_BLOCKS;
    const heights = Number.isFinite(head) && head > 0
      ? Array.from({ length: Math.min(wanted, head) }, (_, index) => head - index)
      : [];
    try {
      const blocks = await Promise.all(heights.map((height) => rpc("block", { height, full: true })));
      const merged = new Map(state.blocks.map((block) => [block.height, block]));
      blocks.forEach((block) => merged.set(block.height, block));
      state.blocks = Array.from(merged.values())
        .sort((left, right) => right.height - left.height)
        .slice(0, HISTORY_BLOCKS);
      renderStats();
      renderActivity();
    } catch (error) {
      renderActivityError(error);
    }
  } catch (error) {
    showConnectionError(error);
  } finally {
    state.refreshing = false;
  }
}

async function start() {
  try {
    state.info = await request("/api/info");
    const primary = state.info.nodes?.[0];
    if (primary) setText("rpc-address", primary.rpc);
  } catch (error) {
    showConnectionError(error);
  }
  await refresh();
  window.setInterval(refresh, REFRESH_MS);
}

byId("search-form").addEventListener("submit", handleSearch);
byId("close-result").addEventListener("click", () => { byId("search-result").hidden = true; });
byId("menu-button").addEventListener("click", () => {
  const navigation = byId("main-nav");
  const open = navigation.classList.toggle("open");
  byId("menu-button").setAttribute("aria-expanded", String(open));
});
byId("main-nav").addEventListener("click", (event) => {
  if (event.target instanceof HTMLAnchorElement) {
    byId("main-nav").classList.remove("open");
    byId("menu-button").setAttribute("aria-expanded", "false");
  }
});

start();
