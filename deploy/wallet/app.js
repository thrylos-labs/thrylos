const RPC_URL = "https://rpc.thrylos.org/";
// The .thry name registry (docs/thry-names.md). A name is required: a wallet is
// created only after the registry has accepted a signed reservation for it.
const NAMES_URL = "https://names.thrylos.org";
const NAME_MIN = 3;
const NAME_MAX = 20;
const CLAIM_TAG = new TextEncoder().encode("thrylos-name-claim-v1");
// The old, unencrypted form: read once so an existing wallet keeps working, and
// removed the moment it is encrypted under a password.
const STORAGE_KEY = "thrylos-testnet-seed-hex";
const ENCRYPTED_KEY = "thrylos-testnet-seed-encrypted";
const PBKDF2_ITERATIONS = 600000;
const MIN_PASSWORD_LENGTH = 8;
const BASE_UNITS_PER_THRY = 1000000000n;
// Matches crates/exec/src/native.rs and crates/node/src/client.rs exactly.
const COIN_PACKAGE_ADDRESS = new Uint8Array(32).fill(6);
const COIN_MODULE_NAME = "coin";
const TRANSFER_FUNCTION = "transfer";
const MIN_PROTOCOL_CALL_GAS = 1000n;
const EXPIRES_AFTER = 1000n;
const INCLUSION_TIMEOUT_MS = 60000;
const INCLUSION_POLL_MS = 500;

const createName = document.getElementById("create-name");
const createNameHint = document.getElementById("create-name-hint");
const createNameError = document.getElementById("create-name-error");
const nameBadge = document.getElementById("name-badge");
const nameBlock = document.getElementById("name-block");
const nameMessage = document.getElementById("name-message");
const claimForm = document.getElementById("claim-form");
const claimName = document.getElementById("claim-name");
const claimNameHint = document.getElementById("claim-name-hint");
const claimNameError = document.getElementById("claim-name-error");
const claimBtn = document.getElementById("claim-btn");
const lockState = document.getElementById("lock-state");
const createPassword = document.getElementById("create-password");
const createPasswordError = document.getElementById("create-password-error");
const emptyImportPassword = document.getElementById("empty-import-password");
const walletImportPassword = document.getElementById("wallet-import-password");
const unlockPassword = document.getElementById("unlock-password");
const unlockError = document.getElementById("unlock-error");
const unlockBtn = document.getElementById("unlock-btn");
const forgetBtn = document.getElementById("forget-btn");
const protectBlock = document.getElementById("protect-block");
const protectPassword = document.getElementById("protect-password");
const protectError = document.getElementById("protect-error");
const protectBtn = document.getElementById("protect-btn");
const lockBtn = document.getElementById("lock-btn");
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
async function addressBytesFromSeed(seed) {
  const pub = await ed.getPublicKeyAsync(seed);
  const encoded = new Uint8Array(33);
  encoded[0] = 0;
  encoded.set(pub, 1);
  const domainInput = new Uint8Array(34);
  domainInput[0] = 4;
  domainInput.set(encoded, 1);
  return blake3(domainInput);
}
async function addressFromSeed(seed) {
  return encodeBech32m("thry", await addressBytesFromSeed(seed));
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

// ---- .thry names ----

// The bare, lowercase form of what was typed: "Alice.thry" -> "alice".
function cleanName(text) {
  const lowered = text.trim().toLowerCase();
  return lowered.endsWith(".thry") ? lowered.slice(0, -5) : lowered;
}

// The registry decides what is reserved or taken; this is only the shape, so a
// typo is caught before a request is made. Mirrors crates/node/src/names.rs.
function nameShapeError(name) {
  if (name.length < NAME_MIN || name.length > NAME_MAX) return "use " + NAME_MIN + " to " + NAME_MAX + " characters";
  if (!/^[a-z0-9-]+$/.test(name)) return "use only a-z, 0-9 and -";
  if (name.startsWith("-") || name.endsWith("-")) return "do not start or end with -";
  if (name.includes("--")) return "do not use --";
  return null;
}

async function namesCall(method, path, body) {
  const res = await fetch(NAMES_URL + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

// {available, reason}, or null if the registry could not be asked.
async function checkAvailability(name) {
  try {
    const { status, data } = await namesCall("GET", "/names/available/" + encodeURIComponent(name));
    if (status !== 200 || !data) return null;
    return { available: data.available === true, reason: data.valid === false ? data.reason : null };
  } catch {
    return null;
  }
}

// Live "is it free?" feedback under a name field.
function watchName(input, hint, error) {
  let timer = null;
  let latest = 0;
  input.addEventListener("input", () => {
    error.hidden = true;
    input.classList.remove("invalid");
    hint.hidden = true;
    hint.className = "field-hint";
    if (timer) clearTimeout(timer);
    const name = cleanName(input.value);
    if (!name) return;
    const shape = nameShapeError(name);
    if (shape) {
      hint.textContent = shape;
      hint.hidden = false;
      return;
    }
    const ticket = ++latest;
    timer = setTimeout(async () => {
      const result = await checkAvailability(name);
      if (ticket !== latest) return;
      hint.hidden = false;
      if (!result) hint.textContent = "could not reach the name registry to check";
      else if (result.reason) hint.textContent = result.reason;
      else if (result.available) { hint.textContent = name + ".thry is free"; hint.className = "field-hint ok"; }
      else hint.textContent = name + ".thry is taken";
    }, 400);
  });
}
watchName(createName, createNameHint, createNameError);
watchName(claimName, claimNameHint, claimNameError);

// The bytes the registry verifies (docs/thry-names.md, "The reservation"):
// tag ++ chain_id(u64le) ++ len(u8) ++ name ++ address(32) ++ timestamp_ms(u64le).
function claimBytes(chainId, name, addressBytes, timestampMs) {
  const nameBytes = new TextEncoder().encode(name);
  return concatBytes([CLAIM_TAG, u64le(chainId), new Uint8Array([nameBytes.length]), nameBytes, addressBytes, u64le(timestampMs)]);
}

// Signs and sends a reservation. Throws an Error with the registry's own words
// when it refuses.
async function reserveName(seed, name) {
  const shape = nameShapeError(name);
  if (shape) throw new Error(shape);
  const status = await fetchStatus();
  const publicKey = await ed.getPublicKeyAsync(seed);
  const addressBytes = await addressBytesFromSeed(seed);
  const timestampMs = Date.now();
  const signature = await ed.signAsync(claimBytes(BigInt(status.chainId), name, addressBytes, timestampMs), seed);
  let reply;
  try {
    reply = await namesCall("POST", "/names", {
      name,
      publicKey: bytesToHex(publicKey),
      timestampMs,
      signature: bytesToHex(signature),
    });
  } catch {
    throw new Error("could not reach the name registry — try again in a moment");
  }
  if (reply.status !== 200) {
    throw new Error((reply.data && reply.data.error && reply.data.error.message) || "the name registry refused that");
  }
  return reply.data;
}

// {status: "confirmed"|"pending"|"none"|"unknown", name?, expiresAtMs?}
async function fetchNameStatus(address) {
  try {
    const { status, data } = await namesCall("GET", "/names/by-address/" + address);
    if (status === 404) return { status: "none" };
    if (status === 200 && data && (data.status === "confirmed" || data.status === "pending")) return data;
    return { status: "unknown" };
  } catch {
    return { status: "unknown" };
  }
}

async function resolveName(name) {
  const { status, data } = await namesCall("GET", "/names/" + encodeURIComponent(name));
  if (status === 200 && data && typeof data.address === "string") return data.address;
  if (status === 404) return null;
  throw new Error("the name registry could not be reached");
}

// What the wallet knows about its own name. Sending is blocked while the wallet
// has no confirmed name; if the registry cannot be reached the state is unknown
// and sending is left alone (a name is a convenience, not part of the chain).
let nameState = { status: "unknown" };
let reservedNameThisSession = null;

function nameBlocksSending() {
  return nameState.status === "none" || nameState.status === "pending";
}

function renderName() {
  const state = nameState.status;
  nameBadge.hidden = state !== "confirmed";
  if (state === "confirmed") nameBadge.textContent = nameState.name + ".thry";
  nameBlock.hidden = state === "confirmed";
  claimForm.hidden = state !== "none";
  if (state === "pending") {
    const when = nameState.expiresAtMs ? new Date(nameState.expiresAtMs).toLocaleString() : "in three days";
    nameMessage.textContent = (reservedNameThisSession ? reservedNameThisSession + ".thry is reserved for you. " : "A name is reserved for this wallet. ") +
      "Confirm it in Discord: run /faucet (or /name) there with your address below. The reservation lapses on " + when + ". You can send once it is confirmed.";
  } else if (state === "none") {
    nameMessage.textContent = "This wallet needs a name. Choose one, then confirm it in Discord with /faucet or /name.";
  } else if (state === "unknown") {
    nameBlock.hidden = false;
    claimForm.hidden = true;
    nameMessage.textContent = "The name registry could not be reached, so this wallet's name could not be checked. Sending still works.";
  }
}

async function refreshNameState() {
  if (!currentAddress) return;
  nameState = await fetchNameStatus(currentAddress);
  renderName();
}

claimBtn.addEventListener("click", async () => {
  setFieldError(claimName, claimNameError, "");
  const name = cleanName(claimName.value);
  const shape = nameShapeError(name);
  if (shape) { setFieldError(claimName, claimNameError, shape); return; }
  claimBtn.disabled = true;
  claimBtn.textContent = "Reserving…";
  try {
    await reserveName(currentSeed, name);
    reservedNameThisSession = name;
    claimName.value = "";
    await refreshNameState();
  } catch (err) {
    setFieldError(claimName, claimNameError, err.message);
  } finally {
    claimBtn.disabled = false;
    claimBtn.textContent = "Reserve name";
  }
});

function loadSeed() {
  try {
    const hex = localStorage.getItem(STORAGE_KEY);
    return hex ? hexToBytes(hex) : null;
  } catch {
    return null;
  }
}

function loadEncrypted() {
  try {
    const text = localStorage.getItem(ENCRYPTED_KEY);
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

// The seed is encrypted with AES-256-GCM under a key from PBKDF2-SHA-256 (WebCrypto,
// 600,000 rounds, a random salt), so what is in storage is useless without the
// password. A wrong password fails GCM's authentication, and is never guessed at.
async function passwordKey(password, salt) {
  const raw = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptSeed(seed, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await passwordKey(password, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, seed));
  return { v: 1, kdf: "pbkdf2-sha256", iterations: PBKDF2_ITERATIONS, salt: bytesToHex(salt), iv: bytesToHex(iv), ciphertext: bytesToHex(ciphertext) };
}

async function decryptSeed(blob, password) {
  if (!blob || blob.v !== 1 || blob.kdf !== "pbkdf2-sha256") throw new Error("this saved wallet is in a format this page does not know");
  // Whatever the file claims, never fewer rounds than this page writes.
  if (!Number.isInteger(blob.iterations) || blob.iterations < PBKDF2_ITERATIONS) throw new Error("the saved wallet asks for too few key-derivation rounds");
  const key = await passwordKey(password, hexToBytes(blob.salt));
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(blob.iv) }, key, hexToBytes(blob.ciphertext));
    return new Uint8Array(plain);
  } catch {
    throw new Error("wrong password");
  }
}

// Encrypts and stores `seed`, and only then removes any unencrypted copy.
async function saveSeedEncrypted(seed, password) {
  const blob = await encryptSeed(seed, password);
  try {
    localStorage.setItem(ENCRYPTED_KEY, JSON.stringify(blob));
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Private window or blocked storage: the wallet still works for this
    // load, it just won't be there on a refresh.
  }
}

function checkPassword(password) {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error("use at least " + MIN_PASSWORD_LENGTH + " characters");
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
  // An unencrypted saved wallet is offered encryption; an encrypted one can be locked.
  const encrypted = loadEncrypted() !== null;
  protectBlock.hidden = encrypted || loadSeed() === null;
  protectPassword.value = "";
  setFieldError(protectPassword, protectError, "");
  lockBtn.hidden = !encrypted;
  lockState.hidden = true;
  nameState = { status: "unknown" };
  renderName();
  await refreshNameState();
  await refreshBalance(currentAddress);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    refreshBalance(currentAddress);
    // A name waiting for Discord is checked as often as the balance.
    if (nameState.status === "pending" || nameState.status === "unknown") refreshNameState();
  }, 10000);
}

function lockWallet() {
  if (pollTimer) clearInterval(pollTimer);
  currentSeed = null;
  currentAddress = null;
  reservedNameThisSession = null;
  nameState = { status: "unknown" };
  keyBlock.hidden = true;
  privateKeyText.textContent = "";
  walletState.hidden = true;
  emptyState.hidden = true;
  lockState.hidden = false;
  unlockPassword.value = "";
  setFieldError(unlockPassword, unlockError, "");
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
  setFieldError(createPassword, createPasswordError, "");
  setFieldError(createName, createNameError, "");
  const name = cleanName(createName.value);
  const shape = nameShapeError(name);
  if (shape) { setFieldError(createName, createNameError, shape); return; }
  try {
    checkPassword(createPassword.value);
  } catch (err) {
    setFieldError(createPassword, createPasswordError, err.message);
    return;
  }
  createBtn.disabled = true;
  createBtn.textContent = "Creating…";
  try {
    await loadCrypto();
    // The key exists only in memory until the registry has accepted the name:
    // if the name is taken or the registry is down, no wallet is created.
    const seed = ed.utils.randomPrivateKey();
    await reserveName(seed, name);
    reservedNameThisSession = name;
    await saveSeedEncrypted(seed, createPassword.value);
    createPassword.value = "";
    createName.value = "";
    await showWallet(seed);
  } catch (err) {
    setFieldError(createName, createNameError, err.message);
  } finally {
    createBtn.disabled = false;
    createBtn.textContent = "Create wallet";
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
    localStorage.removeItem(ENCRYPTED_KEY);
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

function wireImport({ toggleBtn, form, input, passwordInput, errorEl, submitBtn }) {
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
      checkPassword(passwordInput.value);
    } catch (err) {
      setFieldError(input, errorEl, err.message);
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = "Importing…";
    try {
      await saveSeedEncrypted(seed, passwordInput.value);
      passwordInput.value = "";
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
  passwordInput: emptyImportPassword,
  errorEl: emptyImportError,
  submitBtn: emptyImportBtn,
});
wireImport({
  toggleBtn: walletImportToggle,
  form: walletImportForm,
  input: walletImportInput,
  passwordInput: walletImportPassword,
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

// A name typed as the recipient is resolved, then shown as a full address and
// only sent to after a second press. The wallet never sends on a name alone.
let resolvedRecipient = null;
sendAddressInput.addEventListener("input", () => {
  resolvedRecipient = null;
  sendBtn.textContent = "Send";
});

sendBtn.addEventListener("click", async () => {
  setFieldError(sendAddressInput, sendAddressError, "");
  setFieldError(sendAmountInput, sendAmountError, "");
  setSendStatus("", "");

  if (nameBlocksSending()) {
    setSendStatus("error", "this wallet needs a confirmed name before it can send — see the name box above");
    return;
  }

  let recipient, recipientText, amount;
  try {
    recipientText = sendAddressInput.value.trim();
    if (!/^thry1/i.test(recipientText)) {
      const name = cleanName(recipientText);
      const shape = nameShapeError(name);
      if (shape) throw new Error("that is not an address or a name: " + shape);
      let address;
      try {
        address = await resolveName(name);
      } catch (err) {
        throw new Error(err.message);
      }
      if (!address) throw new Error(name + ".thry does not exist");
      if (!resolvedRecipient || resolvedRecipient.name !== name || resolvedRecipient.address !== address) {
        resolvedRecipient = { name, address };
        sendBtn.textContent = "Confirm and send";
        setSendStatus("pending", name + ".thry is ", {code: address}, ". Check this is the right address, then press Confirm and send.");
        return;
      }
      recipientText = address;
    }
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
    resolvedRecipient = null;
    refreshBalance(currentAddress);
  } catch (err) {
    setSendStatus("error", "could not send: " + err.message);
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = "Send";
  }
});

unlockBtn.addEventListener("click", async () => {
  setFieldError(unlockPassword, unlockError, "");
  unlockBtn.disabled = true;
  unlockBtn.textContent = "Unlocking…";
  try {
    const seed = await decryptSeed(loadEncrypted(), unlockPassword.value);
    unlockPassword.value = "";
    await showWallet(seed);
  } catch (err) {
    setFieldError(unlockPassword, unlockError, err.message);
  } finally {
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock";
  }
});
unlockPassword.addEventListener("keydown", (event) => {
  if (event.key === "Enter") unlockBtn.click();
});

let forgetArmed = false;
forgetBtn.addEventListener("click", () => {
  if (!forgetArmed) {
    forgetArmed = true;
    forgetBtn.textContent = "Click again: this deletes the saved wallet for good";
    setTimeout(() => {
      forgetArmed = false;
      forgetBtn.textContent = "forgot the password? remove this wallet";
    }, 4000);
    return;
  }
  try {
    localStorage.removeItem(ENCRYPTED_KEY);
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
  forgetArmed = false;
  forgetBtn.textContent = "forgot the password? remove this wallet";
  lockState.hidden = true;
  emptyState.hidden = false;
});

protectBtn.addEventListener("click", async () => {
  setFieldError(protectPassword, protectError, "");
  try {
    checkPassword(protectPassword.value);
  } catch (err) {
    setFieldError(protectPassword, protectError, err.message);
    return;
  }
  protectBtn.disabled = true;
  protectBtn.textContent = "Encrypting…";
  try {
    await saveSeedEncrypted(currentSeed, protectPassword.value);
    protectPassword.value = "";
    protectBlock.hidden = true;
    lockBtn.hidden = false;
  } catch (err) {
    setFieldError(protectPassword, protectError, "could not encrypt: " + err.message);
  } finally {
    protectBtn.disabled = false;
    protectBtn.textContent = "Encrypt";
  }
});

lockBtn.addEventListener("click", lockWallet);

(async function init() {
  // Crypto must be loaded before anything in storage can be decoded, so this
  // always runs first — cheap, and avoids a load-order bug where a real saved
  // wallet silently looks like "none found".
  await loadCrypto();
  if (loadEncrypted()) {
    emptyState.hidden = true;
    lockState.hidden = false;
    return;
  }
  const seed = loadSeed();
  if (seed) {
    await showWallet(seed);
  }
})();
