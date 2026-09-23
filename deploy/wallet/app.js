const RPC_URL = "https://rpc.thrylos.org/";
const STORAGE_KEY = "thrylos-testnet-seed-hex";
const BASE_UNITS_PER_THRY = 1000000000n;
// Matches crates/exec/src/native.rs and crates/node/src/client.rs exactly.
const COIN_PACKAGE_ADDRESS = new Uint8Array(32).fill(6);
const COIN_MODULE_NAME = "coin";
const TRANSFER_FUNCTION = "transfer";
const MIN_PROTOCOL_CALL_GAS = 1000n;
const EXPIRES_AFTER = 1000n;
const INCLUSION_TIMEOUT_MS = 60000;
const INCLUSION_POLL_MS = 500;

const emptyState = document.getElementById("empty-state");
const walletState = document.getElementById("wallet-state");
const createBtn = document.getElementById("create-btn");
const addressText = document.getElementById("address-text");
const copyBtn = document.getElementById("copy-btn");
const balanceFigure = document.getElementById("balance-figure");
const balanceMeta = document.getElementById("balance-meta");
const refreshBtn = document.getElementById("refresh-btn");
const resetBtn = document.getElementById("reset-btn");
const revealBtn = document.getElementById("reveal-btn");
const keyBlock = document.getElementById("key-block");
const privateKeyText = document.getElementById("private-key-text");
const copyKeyBtn = document.getElementById("copy-key-btn");
const emptyImportToggle = document.getElementById("empty-import-toggle");
const emptyImportForm = document.getElementById("empty-import-form");
const emptyImportInput = document.getElementById("empty-import-input");
const emptyImportError = document.getElementById("empty-import-error");
const emptyImportBtn = document.getElementById("empty-import-btn");
const walletImportToggle = document.getElementById("wallet-import-toggle");
const walletImportForm = document.getElementById("wallet-import-form");
const walletImportInput = document.getElementById("wallet-import-input");
const walletImportError = document.getElementById("wallet-import-error");
const walletImportBtn = document.getElementById("wallet-import-btn");
const sendAddressInput = document.getElementById("send-address");
const sendAmountInput = document.getElementById("send-amount");
const sendAddressError = document.getElementById("send-address-error");
const sendAmountError = document.getElementById("send-amount-error");
const sendBtn = document.getElementById("send-btn");
const sendStatus = document.getElementById("send-status");

let ed, blake3, bytesToHex, hexToBytes;
let pollTimer = null;
let currentSeed = null;
let currentAddress = null;

async function loadCrypto() {
  [ed, { blake3 }, { bytesToHex, hexToBytes }] = await Promise.all([
    import("./noble.js").then((m) => m.ed),
    import("./noble.js"),
    import("./noble.js"),
  ]);
}

// ---- bech32m, matching crates/text/src/address.rs exactly (prefix "thry") ----
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [
  [1, 0x3b6a57b2], [2, 0x26508e6d], [4, 0x1ea119fa], [8, 0x3d4233dd], [16, 0x2a1462b3],
];
const BECH32M_CONST = 0x2bc830a3;
const ADDRESS_TEXT_LENGTH = 4 + 1 + 52 + 6; // "thry" + "1" + 52 data chars + 6 checksum chars

function polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (const [mask, gen] of GENERATOR) if (top & mask) checksum ^= gen;
  }
  return checksum >>> 0;
}
function expand(prefix) {
  const out = [];
  for (const c of prefix) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of prefix) out.push(c.charCodeAt(0) & 31);
  return out;
}
function toFiveBit(bytes) {
  const bits = [];
  for (const b of bytes) for (const mask of [128, 64, 32, 16, 8, 4, 2, 1]) bits.push((b & mask) !== 0);
  const out = [];
  for (let i = 0; i < bits.length; i += 5) {
    let v = 0;
    for (let j = 0; j < 5; j++) v = v * 2 + (bits[i + j] ? 1 : 0);
    out.push(v);
  }
  return out;
}
function fromFiveBit(values) {
  const bits = [];
  for (const v of values) for (const mask of [16, 8, 4, 2, 1]) bits.push((v & mask) !== 0);
  const whole = Math.floor(bits.length / 8) * 8;
  for (let i = whole; i < bits.length; i++) if (bits[i]) return null;
  const out = [];
  for (let i = 0; i < whole; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = byte * 2 + (bits[i + j] ? 1 : 0);
    out.push(byte);
  }
  return out;
}
function checksum(prefix, data) {
  const values = expand(prefix).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ BECH32M_CONST;
  const out = [];
  for (const shift of [25, 20, 15, 10, 5, 0]) out.push((mod >>> shift) & 31);
  return out;
}
function encodeBech32m(prefix, bytes) {
  const data = toFiveBit(bytes);
  const cs = checksum(prefix, data);
  return prefix + "1" + data.concat(cs).map((v) => CHARSET[v]).join("");
}

/** Mirrors crates/text/src/address.rs's `parse_address`. Throws with a
 *  human-readable reason, in the same "what's wrong first" order. */
function decodeAddress(text) {
  text = text.trim();
  if (!text) throw new Error("enter an address");
  if (text.length === 64 && /^[0-9a-fA-F]+$/.test(text)) {
    throw new Error("this looks like raw hex, not an address — addresses start thry1…");
  }
  const hasLower = /[a-z]/.test(text);
  const hasUpper = /[A-Z]/.test(text);
  if (hasLower && hasUpper) throw new Error("the address mixes upper and lower case");
  const lower = text.toLowerCase();
  const sep = lower.lastIndexOf("1");
  if (sep === -1) throw new Error("this is not an address: it should start thry1");
  const prefix = lower.slice(0, sep);
  if (prefix !== "thry") throw new Error(`this address starts "${prefix}", not "thry" — it is for something else`);
  const values = [];
  for (const ch of lower.slice(sep + 1)) {
    const idx = CHARSET.indexOf(ch);
    if (idx === -1) throw new Error(`"${ch}" cannot appear in an address`);
    values.push(idx);
  }
  if (lower.length !== ADDRESS_TEXT_LENGTH) {
    throw new Error(`the address is ${lower.length} characters, not ${ADDRESS_TEXT_LENGTH} — it looks ${lower.length < ADDRESS_TEXT_LENGTH ? "truncated" : "too long"}`);
  }
  if (polymod(expand(prefix).concat(values)) !== BECH32M_CONST) {
    throw new Error("the address has a typo — its checksum does not match");
  }
  const bytes = fromFiveBit(values.slice(0, 52));
  if (!bytes || bytes.length !== 32) throw new Error("this is not an address");
  return new Uint8Array(bytes);
}

// address = bech32m(blake3([DomainTag::AddressV1=4] ++ [Scheme::Ed25519=0] ++ pubkey))
async function addressFromSeed(seed) {
  const pub = await ed.getPublicKeyAsync(seed);
  const encoded = new Uint8Array(33);
  encoded[0] = 0;
  encoded.set(pub, 1);
  const domainInput = new Uint8Array(34);
  domainInput[0] = 4;
  domainInput.set(encoded, 1);
  const addressBytes = blake3(domainInput);
  return encodeBech32m("thry", addressBytes);
}

// ---- Amounts ----
function formatAmount(baseUnitsStr) {
  const n = BigInt(baseUnitsStr);
  const whole = n / BASE_UNITS_PER_THRY;
  const frac = n % BASE_UNITS_PER_THRY;
  let text = whole.toLocaleString("en-US");
  if (frac !== 0n) {
    const fracStr = frac.toString().padStart(9, "0").replace(/0+$/, "");
    text += "." + fracStr;
  }
  return text;
}
/** "2.5" -> 2500000000n base units. Throws on anything that is not a plain
 *  positive decimal with at most 9 fractional digits. */
function parseAmountToBaseUnits(text) {
  text = text.trim();
  if (!/^\d+(\.\d+)?$/.test(text)) throw new Error("enter an amount like 2.5");
  const [wholeStr, fracStr = ""] = text.split(".");
  if (fracStr.length > 9) throw new Error("THRY has at most 9 decimal places");
  const total = BigInt(wholeStr) * BASE_UNITS_PER_THRY + BigInt(fracStr.padEnd(9, "0") || "0");
  if (total === 0n) throw new Error("enter an amount greater than zero");
  return total;
}

// ---- Canonical codec, matching crates/types/src/codec.rs exactly ----
function u64le(n) {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function u32le(n) {
  const b = new Uint8Array(4);
  let v = BigInt(n);
  for (let i = 0; i < 4; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function u128le(n) {
  const b = new Uint8Array(16);
  let v = BigInt(n);
  for (let i = 0; i < 16; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
// Vec<u8>: u32 length prefix + raw bytes.
function bytesField(bytes) {
  return concatBytes([u32le(bytes.length), bytes]);
}
// Vec<Vec<u8>>: u32 length prefix + each item as a bytesField.
function vecOfBytesFields(items) {
  return concatBytes([u32le(items.length), ...items.map(bytesField)]);
}

/** Builds and signs a native THRY transfer, byte-for-byte identical to
 *  crates/node/src/client.rs's `signed_transfer`. Returns the encoded
 *  transaction ready for `send_transaction`, plus its hash. */
async function buildSignedTransfer(seed, { chainId, sequence, expiry, recipient, amount, maxFeePerGas }) {
  const pub = await ed.getPublicKeyAsync(seed);
  const senderField = concatBytes([new Uint8Array([0]), pub]); // PublicKey: [scheme=0] + 32 bytes

  const moveCall = concatBytes([
    COIN_PACKAGE_ADDRESS,
    bytesField(new TextEncoder().encode(COIN_MODULE_NAME)),
    bytesField(new TextEncoder().encode(TRANSFER_FUNCTION)),
    bytesField(new Uint8Array(0)), // type_arguments: none
    vecOfBytesFields([recipient, u128le(amount)]),
  ]);

  const body = concatBytes([
    u64le(chainId),
    senderField,
    u64le(sequence),
    u64le(expiry),
    u64le(MIN_PROTOCOL_CALL_GAS),
    u64le(maxFeePerGas),
    u32le(0), // declared_inputs: none — balances are not Move objects
    moveCall,
  ]);

  const signature = await ed.signAsync(body, seed);
  const signatureField = concatBytes([new Uint8Array([0]), signature]); // Signature: [scheme=0] + 64 bytes
  const full = concatBytes([body, signatureField]);

  // hash = blake3([DomainTag::TransactionV1=3] ++ full)
  const hash = blake3(concatBytes([new Uint8Array([3]), full]));
  return { hex: bytesToHex(full), hash: bytesToHex(hash) };
}

// ---- RPC ----
async function rpcCall(method, params) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || "the node refused that request");
  return data.result;
}
const fetchStatus = () => rpcCall("status", {});
const fetchAccount = (address) => rpcCall("account", { address });

function loadSeed() {
  try {
    const hex = localStorage.getItem(STORAGE_KEY);
    return hex ? hexToBytes(hex) : null;
  } catch {
    return null;
  }
}
function saveSeed(seed) {
  try {
    localStorage.setItem(STORAGE_KEY, bytesToHex(seed));
  } catch {
    // Private window or blocked storage: the wallet still works for this
    // load, it just won't be there on a refresh.
  }
}

async function showWallet(seed) {
  emptyState.hidden = true;
  walletState.hidden = false;
  currentSeed = seed;
  currentAddress = await addressFromSeed(seed);
  addressText.textContent = currentAddress;
  // A previous wallet's key/import panels must not carry over onto this one.
  keyBlock.hidden = true;
  revealBtn.textContent = "Show private key";
  walletImportForm.hidden = true;
  setFieldError(walletImportInput, walletImportError, "");
  walletImportInput.value = "";
  await refreshBalance(currentAddress);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => refreshBalance(currentAddress), 10000);
}

async function refreshBalance(address) {
  balanceMeta.classList.remove("error");
  setSpinner(balanceMeta, "checking…");
  try {
    const account = await fetchAccount(address);
    balanceFigure.textContent = formatAmount(account.balance);
    balanceMeta.textContent = "height " + account.height;
  } catch (err) {
    balanceFigure.textContent = "—";
    balanceMeta.classList.add("error");
    balanceMeta.textContent = "could not reach the network — retrying";
  }
}

createBtn.addEventListener("click", async () => {
  createBtn.disabled = true;
  createBtn.textContent = "Creating…";
  try {
    await loadCrypto();
    const seed = ed.utils.randomPrivateKey();
    saveSeed(seed);
    await showWallet(seed);
  } catch (err) {
    createBtn.disabled = false;
    createBtn.textContent = "Create wallet";
    alertInline("Could not create a wallet: " + err.message);
  }
});

refreshBtn.addEventListener("click", () => {
  if (currentAddress) refreshBalance(currentAddress);
});

let resetArmed = false;
resetBtn.addEventListener("click", () => {
  if (!resetArmed) {
    resetArmed = true;
    resetBtn.textContent = "Click again to confirm";
    setTimeout(() => {
      resetArmed = false;
      resetBtn.textContent = "New wallet";
    }, 3000);
    return;
  }
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
  if (pollTimer) clearInterval(pollTimer);
  currentSeed = null;
  currentAddress = null;
  walletState.hidden = true;
  emptyState.hidden = false;
  resetArmed = false;
  resetBtn.textContent = "New wallet";
});

async function copyFrom(sourceEl, button) {
  const text = sourceEl.textContent;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const range = document.createRange();
    range.selectNodeContents(sourceEl);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  const original = button.textContent;
  button.textContent = "Copied";
  button.classList.add("copied");
  setTimeout(() => {
    button.textContent = original;
    button.classList.remove("copied");
  }, 1500);
}

copyBtn.addEventListener("click", () => copyFrom(addressText, copyBtn));
copyKeyBtn.addEventListener("click", () => copyFrom(privateKeyText, copyKeyBtn));

revealBtn.addEventListener("click", () => {
  const showing = !keyBlock.hidden;
  if (showing) {
    keyBlock.hidden = true;
    revealBtn.textContent = "Show private key";
    return;
  }
  privateKeyText.textContent = bytesToHex(currentSeed);
  keyBlock.hidden = false;
  revealBtn.textContent = "Hide private key";
});

/** "a1b2…" -> Uint8Array(32), or throws with a message fit to show inline. */
function parseSeedHex(text) {
  text = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) {
    throw new Error("a private key is 64 hex characters (0-9, a-f)");
  }
  return hexToBytes(text);
}

function wireImport({ toggleBtn, form, input, errorEl, submitBtn }) {
  toggleBtn.addEventListener("click", () => {
    form.hidden = !form.hidden;
    if (form.hidden) {
      input.value = "";
      setFieldError(input, errorEl, "");
    }
  });
  submitBtn.addEventListener("click", async () => {
    setFieldError(input, errorEl, "");
    let seed;
    try {
      await loadCrypto();
      seed = parseSeedHex(input.value);
    } catch (err) {
      setFieldError(input, errorEl, err.message);
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = "Importing…";
    try {
      saveSeed(seed);
      await showWallet(seed);
      form.hidden = true;
      input.value = "";
    } catch (err) {
      setFieldError(input, errorEl, "could not load that wallet: " + err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Import";
    }
  });
}

wireImport({
  toggleBtn: emptyImportToggle,
  form: emptyImportForm,
  input: emptyImportInput,
  errorEl: emptyImportError,
  submitBtn: emptyImportBtn,
});
wireImport({
  toggleBtn: walletImportToggle,
  form: walletImportForm,
  input: walletImportInput,
  errorEl: walletImportError,
  submitBtn: walletImportBtn,
});

function alertInline(message) {
  balanceMeta.classList.add("error");
  balanceMeta.textContent = message;
}

function setFieldError(input, errorEl, message) {
  if (message) {
    input.classList.add("invalid");
    errorEl.textContent = message;
    errorEl.hidden = false;
  } else {
    input.classList.remove("invalid");
    errorEl.hidden = true;
  }
}

function setSpinner(el, text) {
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  el.replaceChildren(spinner, " " + text);
}

// `parts` are plain strings, or {code: "..."} for monospace. Everything is
// added as text nodes, so nothing (including server-supplied error text) is
// ever parsed as HTML.
function setSendStatus(kind, ...parts) {
  const empty = parts.length === 0 || parts[0] === "";
  sendStatus.hidden = empty;
  sendStatus.className = "send-status" + (kind ? " " + kind : "");
  sendStatus.replaceChildren();
  if (empty) return;
  for (const part of parts) {
    if (typeof part === "string") {
      sendStatus.append(part);
    } else if (part.spinner) {
      const spinner = document.createElement("span");
      spinner.className = "spinner";
      sendStatus.append(spinner, " ");
    } else {
      const code = document.createElement("code");
      code.textContent = part.code;
      sendStatus.append(code);
    }
  }
}

sendBtn.addEventListener("click", async () => {
  setFieldError(sendAddressInput, sendAddressError, "");
  setFieldError(sendAmountInput, sendAmountError, "");
  setSendStatus("", "");

  let recipient, recipientText, amount;
  try {
    recipientText = sendAddressInput.value.trim();
    recipient = decodeAddress(recipientText);
  } catch (err) {
    setFieldError(sendAddressInput, sendAddressError, err.message);
    return;
  }
  try {
    amount = parseAmountToBaseUnits(sendAmountInput.value);
  } catch (err) {
    setFieldError(sendAmountInput, sendAmountError, err.message);
    return;
  }
  if (recipientText === currentAddress) {
    setFieldError(sendAddressInput, sendAddressError, "that is your own address — nothing needs to be sent");
    return;
  }

  sendBtn.disabled = true;
  sendBtn.textContent = "Sending…";
  setSendStatus("pending", {spinner: true}, "checking balance…");
  try {
    const status = await fetchStatus();
    const chainId = BigInt(status.chainId);
    const height = BigInt(status.latest.height);
    const baseFee = BigInt(status.baseFee);
    const maxFeePerGas = baseFee * 2n > 1n ? baseFee * 2n : 1n;
    const maximumFee = MIN_PROTOCOL_CALL_GAS * maxFeePerGas;

    const account = await fetchAccount(currentAddress);
    const sequence = BigInt(account.nextSequenceNumber);
    const balance = BigInt(account.balance);
    const needed = amount + maximumFee;
    if (needed > balance) {
      setSendStatus("error", `not enough THRY: you have ${formatAmount(balance)} THRY, but ${formatAmount(amount)} THRY plus a maximum fee of ${formatAmount(maximumFee)} THRY is needed`);
      return;
    }

    setSendStatus("pending", {spinner: true}, "signing…");
    const { hex, hash } = await buildSignedTransfer(currentSeed, {
      chainId, sequence, expiry: height + EXPIRES_AFTER, recipient, amount, maxFeePerGas,
    });

    setSendStatus("pending", {spinner: true}, "submitting…");
    const submitted = await rpcCall("send_transaction", { transaction: hex });
    if (submitted.hash !== hash) {
      setSendStatus("error", "the network reported a different transaction hash than expected — not confirming this as sent");
      return;
    }

    setSendStatus("pending", {spinner: true}, "waiting for inclusion…");
    const started = Date.now();
    let included = null;
    while (Date.now() - started < INCLUSION_TIMEOUT_MS) {
      try {
        const found = await rpcCall("transaction", { hash });
        if (found.status === "included") { included = found; break; }
      } catch {
        // Not found yet is normal while it is still in flight.
      }
      await new Promise((r) => setTimeout(r, INCLUSION_POLL_MS));
    }

    if (!included) {
      setSendStatus("error", "sent (", {code: hash.slice(0, 16) + "…"}, ") but not yet included after 60s — it may still land; check the explorer");
      return;
    }
    if (included.outcome && included.outcome.status === "aborted") {
      setSendStatus("error", `included in block ${included.height} but aborted: ${included.outcome.message || included.outcome.reason || "unknown reason"}`);
      return;
    }
    setSendStatus("success", `sent — included in block ${included.height}. `, {code: hash.slice(0, 16) + "…"});
    sendAddressInput.value = "";
    sendAmountInput.value = "";
    refreshBalance(currentAddress);
  } catch (err) {
    setSendStatus("error", "could not send: " + err.message);
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = "Send";
  }
});

(async function init() {
  // Crypto must be loaded before loadSeed() can decode anything from
  // storage, so this always runs first — cheap, and avoids a load-order
  // bug where a real saved wallet silently looks like "none found".
  await loadCrypto();
  const seed = loadSeed();
  if (seed) {
    await showWallet(seed);
  }
})();
