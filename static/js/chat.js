const NOBLE_MLKEM_URL = "/static/vendor/noble-post-quantum/ml-kem.bundle.js";
const STORE_PREFIX = "obsidian-wire:v1:";
const CONTACT_TYPE = "obsidian-wire/contact/v1";
const CONTACT_QR_PREFIX = "OW1:";
const BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const ALGORITHM = "ML-KEM-768";

const enc = new TextEncoder();
const dec = new TextDecoder();

const state = {
  me: null,
  identity: null,
  contactCard: null,
  contacts: [],
  activeContact: null,
  messages: [],
  mlkem: null,
  scanStream: null,
  scanTimer: null,
};

const els = {
  cryptoStatus: document.querySelector("#cryptoStatus"),
  accountName: document.querySelector("#accountName"),
  myFingerprint: document.querySelector("#myFingerprint"),
  contactsList: document.querySelector("#contactsList"),
  conversationKicker: document.querySelector("#conversationKicker"),
  conversationTitle: document.querySelector("#conversationTitle"),
  peerFingerprint: document.querySelector("#peerFingerprint"),
  messageLog: document.querySelector("#messageLog"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  sendButton: document.querySelector("#sendButton"),
  copyCardButton: document.querySelector("#copyCardButton"),
  manualContact: document.querySelector("#manualContact"),
  importContactButton: document.querySelector("#importContactButton"),
  systemNotice: document.querySelector("#systemNotice"),
  qrCanvas: document.querySelector("#qrCanvas"),
  scanContactButton: document.querySelector("#scanContactButton"),
  scanDialog: document.querySelector("#scanDialog"),
  scanVideo: document.querySelector("#scanVideo"),
  scanStatus: document.querySelector("#scanStatus"),
};

function setStatus(text, mode = "pending") {
  els.cryptoStatus.textContent = text;
  els.cryptoStatus.classList.toggle("pending", mode === "pending");
  els.cryptoStatus.classList.toggle("danger", mode === "danger");
}

function notice(text) {
  els.systemNotice.textContent = text;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base45Encode(bytes) {
  let output = "";
  for (let i = 0; i < bytes.length; i += 2) {
    if (i + 1 < bytes.length) {
      let value = bytes[i] * 256 + bytes[i + 1];
      const third = Math.floor(value / (45 * 45));
      value -= third * 45 * 45;
      const second = Math.floor(value / 45);
      const first = value % 45;
      output += BASE45_ALPHABET[first] + BASE45_ALPHABET[second] + BASE45_ALPHABET[third];
    } else {
      const second = Math.floor(bytes[i] / 45);
      const first = bytes[i] % 45;
      output += BASE45_ALPHABET[first] + BASE45_ALPHABET[second];
    }
  }
  return output;
}

function base45Decode(value) {
  const numbers = Array.from(value, (char) => BASE45_ALPHABET.indexOf(char));
  if (numbers.some((item) => item < 0)) throw new Error("QR invalido.");

  const bytes = [];
  for (let i = 0; i < numbers.length; ) {
    if (i + 2 < numbers.length) {
      const decoded = numbers[i] + numbers[i + 1] * 45 + numbers[i + 2] * 45 * 45;
      if (decoded > 0xffff) throw new Error("QR invalido.");
      bytes.push(Math.floor(decoded / 256), decoded % 256);
      i += 3;
    } else if (i + 1 < numbers.length) {
      const decoded = numbers[i] + numbers[i + 1] * 45;
      if (decoded > 0xff) throw new Error("QR invalido.");
      bytes.push(decoded);
      i += 2;
    } else {
      throw new Error("QR incompleto.");
    }
  }
  return new Uint8Array(bytes);
}

function safeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function storeKey(name) {
  return `${STORE_PREFIX}${state.me.uuid}:${name}`;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function groupFingerprint(value) {
  return value.match(/.{1,4}/g).slice(0, 8).join(" ");
}

async function fingerprintForPublicKey(publicKeyB64) {
  const digest = await sha256(base64ToBytes(publicKeyB64));
  return groupFingerprint(hex(digest));
}

async function loadCryptoEngine() {
  if (!window.crypto?.subtle) {
    throw new Error("WebCrypto indisponivel neste navegador.");
  }
  const module = await import(NOBLE_MLKEM_URL);
  if (!module.ml_kem768) {
    throw new Error("ML-KEM-768 indisponivel na biblioteca.");
  }
  state.mlkem = module.ml_kem768;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    credentials: "same-origin",
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return response.json();
}

async function ensureIdentity() {
  const keyName = storeKey("identity");
  const stored = safeJsonParse(localStorage.getItem(keyName));
  if (stored?.algorithm === ALGORITHM && stored.publicKey && stored.secretKey) {
    stored.fingerprint = await fingerprintForPublicKey(stored.publicKey);
    return stored;
  }

  const keys = state.mlkem.keygen();
  const identity = {
    algorithm: ALGORITHM,
    publicKey: bytesToBase64(keys.publicKey),
    secretKey: bytesToBase64(keys.secretKey),
    createdAt: new Date().toISOString(),
  };
  identity.fingerprint = await fingerprintForPublicKey(identity.publicKey);
  localStorage.setItem(keyName, JSON.stringify(identity));
  return identity;
}

async function buildContactCard() {
  return {
    type: CONTACT_TYPE,
    version: 1,
    uuid: state.me.uuid,
    username: state.me.username,
    algorithm: ALGORITHM,
    publicKey: state.identity.publicKey,
    fingerprint: state.identity.fingerprint,
  };
}

function compactContactCard(card) {
  return {
    t: "owc1",
    u: card.uuid,
    n: card.username,
    a: card.algorithm,
    p: card.publicKey,
    f: card.fingerprint,
  };
}

function expandCompactContactCard(card) {
  if (!card || card.t !== "owc1") return card;
  return {
    type: CONTACT_TYPE,
    version: 1,
    uuid: card.u,
    username: card.n,
    algorithm: card.a,
    publicKey: card.p,
    fingerprint: card.f,
  };
}

function encodeContactCardForQr(card) {
  return CONTACT_QR_PREFIX + base45Encode(enc.encode(JSON.stringify(compactContactCard(card))));
}

function decodeContactPayload(rawPayload) {
  const payload = rawPayload.trim();
  if (payload.startsWith(CONTACT_QR_PREFIX)) {
    const decoded = dec.decode(base45Decode(payload.slice(CONTACT_QR_PREFIX.length)));
    return expandCompactContactCard(safeJsonParse(decoded));
  }
  return expandCompactContactCard(safeJsonParse(payload));
}

function loadContacts() {
  const contacts = safeJsonParse(localStorage.getItem(storeKey("contacts")));
  state.contacts = Array.isArray(contacts) ? contacts : [];
}

function saveContacts() {
  localStorage.setItem(storeKey("contacts"), JSON.stringify(state.contacts));
}

function renderContacts() {
  els.contactsList.innerHTML = "";
  if (!state.contacts.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Escaneie um QR presencial ou cole um cartao para abrir um canal.";
    els.contactsList.append(empty);
    return;
  }

  for (const contact of state.contacts) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `contact-item${state.activeContact?.uuid === contact.uuid ? " active" : ""}`;
    button.innerHTML = `
      <span class="contact-avatar">${escapeHtml(initials(contact.username))}</span>
      <span>
        <span class="contact-name">${escapeHtml(contact.username)}</span>
        <span class="contact-fingerprint">${escapeHtml(contact.fingerprint)}</span>
      </span>
    `;
    button.addEventListener("click", () => {
      state.activeContact = contact;
      renderContacts();
      renderConversation();
    });
    els.contactsList.append(button);
  }
}

function renderHeader() {
  els.accountName.textContent = state.me.username;
  els.myFingerprint.textContent = state.identity.fingerprint;
}

function renderConversation() {
  const contact = state.activeContact;
  els.messageLog.innerHTML = "";
  els.messageInput.disabled = !contact;
  els.sendButton.disabled = !contact;

  if (!contact) {
    els.conversationKicker.textContent = "Nenhum contato ativo";
    els.conversationTitle.textContent = "Adicione alguem por QR";
    els.peerFingerprint.textContent = "sem peer";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "O cofre esta pronto para um handshake presencial.";
    els.messageLog.append(empty);
    return;
  }

  els.conversationKicker.textContent = contact.algorithm;
  els.conversationTitle.textContent = contact.username;
  els.peerFingerprint.textContent = contact.fingerprint;

  const visible = state.messages.filter((message) => message.peer_uuid === contact.uuid);
  if (!visible.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Canal aberto. Nenhuma mensagem neste par ainda.";
    els.messageLog.append(empty);
    return;
  }

  for (const message of visible) {
    const bubble = document.createElement("article");
    bubble.className = `message ${message.direction}${message.failed ? " failed" : ""}`;
    const body = document.createElement("div");
    body.textContent = message.failed ? "Falha de autenticacao ou chave local ausente." : message.plaintext;
    const meta = document.createElement("span");
    meta.className = "message-meta";
    meta.textContent = `${message.direction === "out" ? "enviada" : "recebida"} - ${formatTime(message.created_at)}`;
    bubble.append(body, meta);
    els.messageLog.append(bubble);
  }
  els.messageLog.scrollTop = els.messageLog.scrollHeight;
}

async function renderQr() {
  const ctx = els.qrCanvas.getContext("2d");
  ctx.fillStyle = "#eef7f0";
  ctx.fillRect(0, 0, els.qrCanvas.width, els.qrCanvas.height);
  ctx.fillStyle = "#07100b";
  ctx.font = "700 42px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("Gerando QR", els.qrCanvas.width / 2, els.qrCanvas.height / 2);

  const qrPayload = encodeContactCardForQr(state.contactCard);
  const result = await fetchJson("/api/contact-qr", {
    method: "POST",
    body: JSON.stringify({ payload: qrPayload }),
  });

  await new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      ctx.imageSmoothingEnabled = false;
      ctx.fillStyle = "#eef7f0";
      ctx.fillRect(0, 0, els.qrCanvas.width, els.qrCanvas.height);
      ctx.drawImage(image, 0, 0, els.qrCanvas.width, els.qrCanvas.height);
      resolve();
    };
    image.onerror = () => reject(new Error("Nao foi possivel carregar o QR."));
    image.src = result.data_url;
  });
}

async function validateContactCard(card) {
  if (!card || card.type !== CONTACT_TYPE) throw new Error("Cartao invalido.");
  if (card.uuid === state.me.uuid) throw new Error("Esse cartao e seu.");
  if (card.algorithm !== ALGORITHM) throw new Error("Algoritmo incompativel.");
  if (!card.publicKey || !card.username || !card.uuid) throw new Error("Cartao incompleto.");

  const fingerprint = await fingerprintForPublicKey(card.publicKey);
  if (card.fingerprint && card.fingerprint !== fingerprint) {
    throw new Error("Fingerprint nao confere.");
  }

  return {
    type: CONTACT_TYPE,
    uuid: String(card.uuid),
    username: String(card.username).slice(0, 48),
    algorithm: ALGORITHM,
    publicKey: String(card.publicKey),
    fingerprint,
    addedAt: new Date().toISOString(),
  };
}

async function importContactPayload(rawPayload) {
  const card = decodeContactPayload(rawPayload);
  const contact = await validateContactCard(card);
  const index = state.contacts.findIndex((item) => item.uuid === contact.uuid);
  if (index >= 0) {
    state.contacts[index] = contact;
  } else {
    state.contacts.push(contact);
  }
  state.contacts.sort((a, b) => a.username.localeCompare(b.username));
  saveContacts();
  state.activeContact = contact;
  renderContacts();
  renderConversation();
  notice(`${contact.username} adicionado ao cofre.`);
}

async function deriveAesKey(sharedSecret, capsuleB64, aad, copy) {
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-512",
      salt: enc.encode("ObsidianWire/K-Protocol/v1"),
      info: enc.encode(`${ALGORITHM}|AES-256-GCM|${copy}|${capsuleB64}|${aad}`),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptFor(publicKeyB64, plaintext, aad, copy) {
  const encapsulated = state.mlkem.encapsulate(base64ToBytes(publicKeyB64));
  const capsuleBytes = encapsulated.cipherText || encapsulated.ciphertext || encapsulated.cipher_text;
  const sharedSecret = encapsulated.sharedSecret || encapsulated.shared_secret;
  const capsule = bytesToBase64(capsuleBytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(sharedSecret, capsule, aad, copy);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(aad) },
    key,
    enc.encode(plaintext),
  );
  return {
    capsule,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
  };
}

async function decryptMessage(message) {
  try {
    const secretKey = base64ToBytes(state.identity.secretKey);
    const sharedSecret = state.mlkem.decapsulate(base64ToBytes(message.capsule), secretKey);
    const key = await deriveAesKey(sharedSecret, message.capsule, message.aad, message.copy);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(message.iv),
        additionalData: enc.encode(message.aad),
      },
      key,
      base64ToBytes(message.ciphertext),
    );
    return { ...message, plaintext: dec.decode(decrypted), failed: false };
  } catch {
    return { ...message, plaintext: "", failed: true };
  }
}

async function refreshMessages() {
  const payload = await fetchJson("/api/messages");
  state.messages = await Promise.all(payload.messages.map(decryptMessage));
  renderConversation();
}

async function sendMessage(event) {
  event.preventDefault();
  const text = els.messageInput.value.trim();
  const contact = state.activeContact;
  if (!text || !contact) return;

  els.sendButton.disabled = true;
  try {
    const aad = JSON.stringify({
      v: 1,
      alg: `${ALGORITHM}+HKDF-SHA512+AES-256-GCM`,
      sender: state.me.uuid,
      recipient: contact.uuid,
      client_id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
    });
    const recipientCopy = await encryptFor(contact.publicKey, text, aad, "recipient");
    const senderCopy = await encryptFor(state.identity.publicKey, text, aad, "sender");
    await fetchJson("/api/messages", {
      method: "POST",
      body: JSON.stringify({
        recipient_uuid: contact.uuid,
        aad,
        recipient_copy: recipientCopy,
        sender_copy: senderCopy,
      }),
    });
    els.messageInput.value = "";
    await refreshMessages();
  } catch (error) {
    notice(`Envio recusado: ${error.message}`);
  } finally {
    els.sendButton.disabled = !state.activeContact;
  }
}

async function copyContactCard() {
  const payload = encodeContactCardForQr(state.contactCard);
  try {
    await navigator.clipboard.writeText(payload);
    notice("Cartao QR copiado.");
  } catch {
    els.manualContact.value = payload;
    els.manualContact.select();
    notice("Cartao colocado no campo de importacao.");
  }
}

async function startScanner() {
  if (!("BarcodeDetector" in window)) {
    els.scanStatus.textContent = "Este navegador nao expoe BarcodeDetector. Cole o cartao manualmente.";
    return;
  }

  stopScanner();
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  state.scanStream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
    audio: false,
  });
  els.scanVideo.srcObject = state.scanStream;
  await els.scanVideo.play();
  els.scanStatus.textContent = "Camera ativa.";

  state.scanTimer = window.setInterval(async () => {
    try {
      const codes = await detector.detect(els.scanVideo);
      if (!codes.length) return;
      await importContactPayload(codes[0].rawValue);
      els.scanDialog.close();
      stopScanner();
    } catch (error) {
      els.scanStatus.textContent = error.message || "Nao foi possivel ler o QR.";
    }
  }, 420);
}

function stopScanner() {
  if (state.scanTimer) {
    window.clearInterval(state.scanTimer);
    state.scanTimer = null;
  }
  if (state.scanStream) {
    for (const track of state.scanStream.getTracks()) track.stop();
    state.scanStream = null;
  }
  els.scanVideo.srcObject = null;
}

function initials(name) {
  return String(name)
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

function formatTime(value) {
  const date = new Date(value);
  return new Intl.DateTimeFormat("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    day: "2-digit",
    month: "2-digit",
  }).format(date);
}

async function boot() {
  try {
    setStatus("Carregando ML-KEM", "pending");
    state.me = await fetchJson("/api/me");
    await loadCryptoEngine();
    state.identity = await ensureIdentity();
    state.contactCard = await buildContactCard();
    loadContacts();
    renderHeader();
    renderContacts();
    renderConversation();
    await renderQr();
    await refreshMessages();
    setStatus("ML-KEM ativo", "ok");
    notice("Cofre pronto.");
    window.setInterval(refreshMessages, 4500);
  } catch (error) {
    setStatus("Cripto indisponivel", "danger");
    notice(error.message);
  }
}

els.messageForm.addEventListener("submit", sendMessage);
els.copyCardButton.addEventListener("click", copyContactCard);
els.importContactButton.addEventListener("click", async () => {
  try {
    await importContactPayload(els.manualContact.value.trim());
    els.manualContact.value = "";
  } catch (error) {
    notice(error.message);
  }
});
els.scanContactButton.addEventListener("click", async () => {
  els.scanDialog.showModal();
  try {
    await startScanner();
  } catch (error) {
    els.scanStatus.textContent = error.message || "Camera indisponivel.";
  }
});
els.scanDialog.addEventListener("close", stopScanner);

boot();
