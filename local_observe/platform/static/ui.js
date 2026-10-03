"use strict";
const $ = (id) => document.getElementById(id);
let token = "",
  authMode = "",
  role = "",
  view = "incidents",
  rows = [],
  names = {},
  generation = 0,
  detailGeneration = 0,
  pendingCommand = null;
const titles = {
  incidents: "Incidents",
  actions: "Approvals",
  executions: "Executions",
  outbox: "Notifications",
  inventory: "Inventory",
  events: "Events",
  audit: "Audit",
  investigations: "Investigations",
};
const icons = () => lucide.createIcons();
const value = (item) =>
  item === null || item === undefined
    ? "-"
    : typeof item === "object"
      ? JSON.stringify(item, null, 2)
      : String(item);
const payload = (row) => {
  try {
    return JSON.parse(row.payload || "{}");
  } catch {
    return {};
  }
};
async function api(path, body) {
  const loginGeneration = generation;
  const response = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: (authMode === "password" ? "Basic " : "Bearer ") + token,
      "Content-Type": "application/json",
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (loginGeneration !== generation) throw new Error("Sign-in changed. Please retry.");
  if (response.status === 401) {
    signout();
    throw new Error("Authentication required.");
  }
  if (!response.ok)
    throw new Error(
      "Request refused (" + response.status + "). Refresh before retrying.",
    );
  return response.json();
}
// Startup observation from the serving process: recording/off/live, never a build-time label.
const modes = { recording: "RECORDING", off: "OFF", live: "LIVE" };
function setMode(mode) {
  const label = modes[mode] || "UNKNOWN";
  $("environment").textContent = label;
  $("environment").dataset.mode = modes[mode] ? mode : "unknown";
}
async function loadMode() {
  const mine = generation;
  try {
    const runtime = await api("/v1/runtime");
    if (mine === generation) setMode(runtime.notification_mode);
  } catch {
    setMode("");
  }
}
function signout() {
  generation++;
  detailGeneration++;
  token = "";
  for (const id of ["token", "username", "password"]) $(id).value = "";
  role = "";
  rows = [];
  names = {};
  setMode("");
  historyClear();
  reviewClear();
  cyclesClear();
  $("identity").textContent = "Disconnected";
  $("records").replaceChildren();
  for (const id of ["detail-fields", "commands", "evidence", "detail-error"])
    $(id).replaceChildren();
  $("empty").hidden = false;
  $("empty").textContent = "Sign in to view records.";
  for (const id of ["open-count", "approval-count", "delivery-count"])
    $(id).textContent = "-";
  $("detail").close();
  if ($("confirm").open) $("confirm").close("cancel");
  if (!$("login").open) $("login").showModal();
}
function button(label, icon, handler) {
  const b = document.createElement("button");
  b.title = label;
  b.setAttribute("aria-label", label);
  const i = document.createElement("i");
  i.setAttribute("data-lucide", icon);
  b.append(i);
  b.onclick = handler;
  return b;
}
function render() {
  // `#status-filter` lists record statuses and says nothing about a cycle, while `#observer-summary` and
  // `#observer-more` belong to the cycle list. `#list-panel` is one card both views share, so each view
  // hides the other's controls rather than leaving a filter on screen that can only answer "nothing".
  const listed = view === "investigations";
  $("status-filter").hidden = listed;
  $("status-filter").disabled = listed;
  $("observer-summary").hidden = !listed || !$("observer-summary").textContent;
  $("observer-more").hidden = !listed || !cycles.next;
  if (listed) return renderCycles();
  const search = $("search").value.toLowerCase(),
    status = $("status-filter").value;
  const filtered = rows.filter(
    (row) =>
      (!status || row.status === status) &&
      JSON.stringify(row).toLowerCase().includes(search),
  );
  const columns =
    view === "inventory"
      ? ["Name", "Kind", "Host", ""]
      : view === "audit"
        ? ["Operation", "Actor", "Time", ""]
        : [view === "outbox" ? "Delivery" : "Description", "Status", "Resource / host", ""];
  const head = document.createElement("tr");
  for (const text of columns) {
    const th = document.createElement("th");
    th.textContent = text;
    head.append(th);
  }
  $("columns").replaceChildren(head);
  $("records").replaceChildren();
  $("empty").hidden = filtered.length !== 0;
  $("empty").textContent = token
    ? "No matching records."
    : "Sign in to view records.";
  for (const row of filtered) {
    const data = payload(row);
    const display = row.display || {};
    const fields =
      view === "inventory"
        ? [display.resource_name || row.name, row.kind, display.host_name || "Not declared"]
        : view === "audit"
          ? [row.operation || row.kind, row.actor, row.at || row.created_at]
          : [
              (view === "outbox" ? display.delivery_name + ": " : "") +
                (display.description || data.action || "Monitoring record"),
              row.status,
              [display.resource_name || names[row.resource_id] || "Unassigned resource",
                display.host_name && display.host_name !== display.resource_name ? display.host_name : ""].filter(Boolean).join(" / "),
            ];
    const tr = document.createElement("tr");
    fields.forEach((text, index) => {
      const td = document.createElement("td");
      const full = value(text);
      td.textContent = /^[a-f0-9-]{36}$/.test(full) ? full.slice(0, 8) : full;
      td.title = full;
      if (index === 1) td.className = "pill " + (row.status || "");
      tr.append(td);
    });
    const action = document.createElement("td");
    action.append(
      button("Inspect record", "chevron-right", () => details(row)),
    );
    tr.append(action);
    $("records").append(tr);
  }
  icons();
}
async function refresh() {
  if (!token) return;
  if (view === "investigations") return refreshCycles();
  const mine = ++generation;
  $("refresh").disabled = true;
  $("error").hidden = true;
  try {
    // Password verification is bounded server-side; do not burst three KDFs.
    const status = await api("/v1/status");
    if (mine !== generation) return;
    const records = await api(view === "inventory" ? "/v1/inventory" : "/v1/records/" + view);
    if (mine !== generation) return;
    const inventory = view === "inventory" ? records : await api("/v1/inventory");
    if (mine !== generation) return;
    names = Object.fromEntries(inventory.rows.map((row) => [row.id, row.name]));
    rows = records.rows;
    $("open-count").textContent = status.incidents.open || 0;
    $("approval-count").textContent = status.actions.pending || 0;
    $("delivery-count").textContent =
      (status.notifications.pending || 0) + (status.notifications.sending || 0);
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
    render();
  } catch (error) {
    if (mine === generation) {
      $("error").textContent = error.message;
      $("error").hidden = false;
    }
  } finally {
    $("refresh").disabled = false;
  }
}
async function confirmDecision(label, id) {
  $("confirm-title").textContent = label;
  $("confirm-subject").replaceChildren();
  if (Array.isArray(id)) {
    const fields = document.createElement("dl");
    for (const [name, text] of id) {
      const term = document.createElement("dt"), description = document.createElement("dd");
      term.textContent = name;
      description.textContent = text;
      fields.append(term, description);
    }
    $("confirm-subject").append(fields);
  } else $("confirm-subject").textContent = id;
  return new Promise((resolve) => {
    $("confirm").addEventListener(
      "close",
      () => resolve($("confirm").returnValue === "confirm"),
      { once: true },
    );
    $("confirm").returnValue = "cancel";
    $("confirm").showModal();
  });
}
function command(label, icon, path, body, prepare = null) {
  const b = button(label, icon, async () => {
    if (b.disabled || pendingCommand === detailGeneration) return;
    const mine = generation, detail = detailGeneration;
    const current = () => mine === generation && detail === detailGeneration && $("detail").open;
    pendingCommand = detail;
    for (const button of $("commands").children) button.disabled = true;
    $("detail-error").textContent = "";
    try {
      const reviewed = prepare ? await prepare() : { body, subject: $("detail-title").textContent };
      if (!current()) return;
      if (!(await confirmDecision(label, reviewed.subject)) || !current()) return;
      await api(path, reviewed.body);
      if (!current()) return;
      $("detail").close();
      await refresh();
    } catch (error) {
      if (current()) $("detail-error").textContent = error.message;
    } finally {
      if (pendingCommand === detail) pendingCommand = null;
      if (detail === detailGeneration)
        for (const button of $("commands").children) button.disabled = false;
    }
  });
  b.append(document.createTextNode(label));
  return b;
}

async function approvalReview(row) {
  const refused = () => new Error("Approval review is unavailable or does not match this action. " +
    "No decision was sent. Refresh and check the platform approval configuration before retrying.");
  if (!isIdentifier(row.id)) throw refused();
  let review;
  try {
    review = await api("/v1/actions/review?action_id=" + encodeURIComponent(row.id));
  } catch {
    throw refused();
  }
  const object = (value) => value && typeof value === "object" && !Array.isArray(value);
  const exact = (value, keys) => object(value) && Object.keys(value).sort().join() === keys.sort().join();
  const label = (text) => typeof text === "string" && text.length <= 128 && LABEL_TEXT.test(text)
    && !/[\r\n]/.test(text);
  const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
  const request = review?.request, binding = review?.binding, shown = payload(row);
  if (review?.mode === "manual") {
    const fields = ["retry_key", "incident_id", "action", "version", "targets", "parameters", "evidence", "expires_at"];
    // Compare complete request values, allowing harmless object-key reordering while preserving
    // array order. The server's stored action is immutable; no field can be supplied by the caller.
    const stable = (value) => Array.isArray(value) ? value.map(stable) : object(value)
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
    if (!exact(review, ["mode", "action_id", "request", "request_sha256"])
        || review.action_id !== row.id || !isDigest(review.request_sha256)
        || !exact(request, fields) || !exact(shown, fields) || !same(stable(request), stable(shown))
        || !label(request.action) || !label(request.version) || !label(request.retry_key)
        || !isIdentifier(request.incident_id)
        || !Array.isArray(request.targets) || !request.targets.length || request.targets.length > 20
        || !request.targets.every(isIdentifier) || new Set(request.targets).size !== request.targets.length
        || !Array.isArray(request.evidence) || !request.evidence.length || request.evidence.length > 20
        || !request.evidence.every(isIdentifier) || typeof request.expires_at !== "string"
        || !Number.isFinite(Date.parse(request.expires_at))) throw refused();
    return {
      body: { action_id: row.id, decision: "approved" },
      subject: [["Approval scope", "Manual request only. No trusted runner or DAG binding."],
        ["Action ID", row.id], ["Action", request.action], ["Version", request.version],
        ["Targets (exact inventory IDs)", request.targets.join("\n")],
        ["Request SHA-256", review.request_sha256], ["Approval expiry", request.expires_at],
        ["Request (exact JSON)", JSON.stringify(request, null, 2)]],
    };
  }
  if (!exact(review, ["action_id", "request", "request_sha256", "runner", "binding", "binding_sha256"])
      || review.action_id !== row.id || !isDigest(review.binding_sha256)
      || !isDigest(review.request_sha256) || !label(review.runner)
      || !exact(binding, ["action", "version", "targets", "dag", "sha256"])
      || !object(request) || !label(binding.action) || !label(binding.version)
      || typeof binding.dag !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(binding.dag)
      || /[\r\n]/.test(binding.dag) || !isDigest(binding.sha256)
      || !Array.isArray(binding.targets) || !binding.targets.length || binding.targets.length > 20
      || !binding.targets.every(isIdentifier) || new Set(binding.targets).size !== binding.targets.length
      || !exact(request.parameters, []) || !exact(shown.parameters, [])
      || !["action", "version", "targets"].every((key) =>
        same(binding[key], request[key]) && same(request[key], shown[key]))
      || typeof request.expires_at !== "string" || !Number.isFinite(Date.parse(request.expires_at))) throw refused();
  return {
    body: { action_id: row.id, decision: "approved", binding_sha256: review.binding_sha256 },
    subject: [["Action ID", row.id], ["Action", binding.action], ["Version", binding.version],
      ["Targets (exact inventory IDs)", binding.targets.join("\n")], ["DAG", binding.dag],
      ["DAG SHA-256", binding.sha256], ["Binding SHA-256", review.binding_sha256],
      ["Request SHA-256", review.request_sha256], ["Trusted runner", review.runner],
      ["Approval expiry", request.expires_at]],
  };
}
// --- Stored verification history -------------------------------------------------------------
// Read-only, and only inside an execution's detail. One click asks the platform for the ids that
// execution carries; one click on an id asks for that one stored document. Nothing is fetched eagerly,
// polled, retried or written, and nothing here decides that an incident recovered: what comes back is a
// recorded past judgement, labelled as one. The bounds below mirror the server's own contract (64 ids per
// execution, canonical UUIDs, lowercase SHA-256 ids, bounded verdict/reason/instant words) because a
// reply this panel cannot account for is a refusal, never a shorter list to show anyway.
const RECORDS_ROUTE = "/v1/verification/records";
const RECORD_ROUTE = "/v1/verification/record";
const ID_LIMIT = 64; // verification_records.RECORDS_PER_EXECUTION, the writer's own cap.
const DIGEST_TEXT = /^[0-9a-f]{64}$/;
const IDENTIFIER_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LABEL_TEXT = /^[A-Za-z0-9_.:-]{1,128}$/; // state.label, the shape a recorded reason word has.
// `inventory.validation.utc_text` printed: whole seconds to the microsecond, at UTC. One form, tested
// against the whole field, and then checked as a real calendar instant (see `instant`).
const INSTANT_TEXT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(Z|\+00:00)$/;
const DIGEST_LENGTH = 64; // a SHA-256 digest in hex, and nothing else wearing an id's shape
const IDENTIFIER_LENGTH = 36; // canonical UUID text, dashes included
// The length test is not a restatement of `{64}`/`{36}`: it makes "one id, the whole field" a measured
// claim rather than a property of how a regex anchor behaves, and it is what refuses a value that is the
// right characters plus a newline, a trailing space or anything else one character too long to be an id.
const whole = (value, pattern, length) =>
  typeof value === "string" && value.length === length && pattern.test(value);
const isDigest = (value) => whole(value, DIGEST_TEXT, DIGEST_LENGTH);
const isIdentifier = (value) => whole(value, IDENTIFIER_TEXT, IDENTIFIER_LENGTH);
const VERDICT_TEXT = ["cleared", "not_cleared", "unknown"];
// Fixed sentences. The backend's own words, its bodies and its exception classes never reach the screen:
// each of these is the whole answer this panel is able to give about that one state.
const HISTORY_STATES = {
  "not-loaded": "Not loaded.",
  loading: "Loading verification history.",
  empty: "No verification result was recorded for this execution.",
  forbidden: "This sign-in may not read verification history.",
  absent: "This platform has no record of what was asked for.",
  busy: "The platform is busy: nothing was read and nothing was queued.",
  malformed: "The reply was not a verification record this panel can vouch for, so nothing is shown.",
  mismatch: "The reply was about another execution or another record, so nothing is shown.",
  recorded: "The selected record is shown below as it was recorded.",
  unavailable: "Verification history is unavailable.",
};
// One counter for the panel, bumped on every new request, every id selection, every detail change, close,
// reopen and sign-out. A response may touch the screen only while the generation it was asked under is
// still current, this sign-in is still the one that asked, and the dialog is still open — the three tests
// `historyAnswered` makes together, before it lets an answer do anything at all.
const verification = {
  generation: 0,
  execution: "",
  ids: [],
  loading: false,
  recordLoading: false,
};

function historyState(code, text) {
  const line = $("verification-state");
  line.dataset.state = code;
  line.textContent = text === undefined ? HISTORY_STATES[code] : text;
}

function recordState(code) {
  const line = $("verification-record-state");
  line.dataset.state = code;
  line.textContent = code ? HISTORY_STATES[code] : "";
  line.hidden = !code;
}

// Wipes everything this panel put in the dialog, including the two in-flight flags: an answer on its way
// to a closed dialog has nowhere to land, and a reopened detail starts again at "Not loaded.".
function historyClear() {
  verification.generation++;
  verification.execution = "";
  verification.ids = [];
  verification.loading = false;
  verification.recordLoading = false;
  $("verification").hidden = true;
  $("verification-load").disabled = false;
  $("verification-ids").replaceChildren();
  $("verification-result").replaceChildren();
  recordState("");
  historyState("not-loaded");
}

function historyOpen(executionId) {
  // A row whose id is not a canonical UUID is not an execution the server could look up, so the
  // affordance is not offered at all rather than offering a request that can only be refused.
  if (!isIdentifier(executionId)) return;
  $("verification").hidden = false;
  verification.execution = executionId;
}

// A verification read is its own small request: GET, no body, `no-store`, and deliberately *not* the
// shared `api()` helper, whose single generic error sentence would flatten 403/404/503 into one state.
async function historyFetch(path) {
  try {
    const response = await fetch(path, {
      method: "GET",
      cache: "no-store",
      headers: { Authorization: (authMode === "password" ? "Basic " : "Bearer ") + token, Accept: "application/json" },
    });
    if (response.status === 401) return { answer: "session" };
    if (!response.ok)
      return {
        answer: { 403: "forbidden", 404: "absent", 503: "busy" }[response.status] || "refused",
      };
    try {
      return { answer: "ok", body: await response.json() };
    } catch {
      return { answer: "malformed" };
    }
  } catch {
    return { answer: "unreachable" };
  }
}

// The one gate every response passes, and it is passed *before anything happens*: is this still the
// request this panel is waiting for, under the sign-in that asked, in a dialog that is still open? The
// third test is not redundant with the generation counter — `close()` clears `open` synchronously while
// its `close` event (the one that bumps the generation) is still queued — so a completion that lands in
// that gap has nowhere to write. A dropped answer touches no node and performs no side effect,
// sign-out included; only a *current* 401 is allowed to end the session.
function historyAnswered(mine) {
  return mine === verification.generation && !!token && $("detail").open;
}

// The list route's whole answer is one key holding at most 64 ids. Over-cap, a non-list, a second key or
// an id that is not 64 lowercase hex is this panel refusing to read a reply — never a list to trim.
function historyIds(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== "verification_ids") return null;
  const ids = body.verification_ids;
  if (!Array.isArray(ids) || ids.length > ID_LIMIT) return null;
  if (!ids.every(isDigest)) return null;
  // `verification_reader` answers lexical ascending ids, one row each, and the panel lists them in that
  // order and says so. An unsorted or repeated id is therefore not a list to tidy up before display: it
  // is a reply this panel cannot describe, and sorting or de-duplicating one here would be this panel
  // deciding the order it exists to report.
  for (let index = 1; index < ids.length; index++) if (!(ids[index - 1] < ids[index])) return null;
  return ids.slice();
}

// One stored instant as exact UTC microseconds, or `null`. The character test admits the shape; the
// round-trip below is what refuses a field that is in range only after normalisation — `Date.parse`
// happily rolls `2026-02-30` into March, and an instant this panel cannot place exactly is one it must
// not print as a recorded window bound or compare against another. No interpretation, no localisation:
// the text that passes is shown exactly as stored.
function instant(value) {
  if (typeof value !== "string" || value !== value.trim() || !INSTANT_TEXT.test(value)) return null;
  const [year, month, day, hour, minute, second] = value
    .slice(0, 26)
    .split(/[-T:.]/)
    .map(Number);
  const read = new Date(0);
  read.setUTCFullYear(year, month - 1, day);
  read.setUTCHours(hour, minute, second, 0);
  return year >= 1 && read.getUTCFullYear() === year && read.getUTCMonth() === month - 1 && read.getUTCDate() === day
    && read.getUTCHours() === hour && read.getUTCMinutes() === minute && read.getUTCSeconds() === second
    ? BigInt(read.getTime()) * 1000n + BigInt(value.slice(20, 26))
    : null;
}

// Only four readable fields are taken out of the document, and only after both identity fields name
// what was asked for. `"mismatch"` is its own answer because "a reply about something else" is a
// different fact from "a reply this panel cannot read", and only one of them is the operator's problem.
// Every field is judged on its own type first: `LABEL_TEXT.test(123)` would otherwise read the *text*
// `"123"` out of a number, and a document whose fields are not the fields it names is unreadable, not
// coercible. The two instant comparisons are the document agreeing with itself — a window that runs
// backwards, or a record stamped before the window it judges ended, is not a record of anything.
function historyRecord(body, wantedId, executionId) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  if (body.verification_id !== wantedId || body.execution_id !== executionId) return "mismatch";
  if (VERDICT_TEXT.indexOf(body.verdict) < 0) return null;
  if (typeof body.reason !== "string" || body.reason !== body.reason.trim() || !LABEL_TEXT.test(body.reason)) return null;
  const window = body.window;
  if (
    !window ||
    typeof window !== "object" ||
    Array.isArray(window) ||
    Object.keys(window).length !== 2 ||
    !("start" in window) ||
    !("end" in window)
  )
    return null;
  const start = instant(window.start);
  const end = instant(window.end);
  const recorded = instant(body.recorded_at);
  if (start === null || end === null || recorded === null) return null;
  if (!(start < end) || !(recorded >= end)) return null;
  return {
    verdict: body.verdict,
    reason: body.reason,
    start: window.start,
    end: window.end,
    recordedAt: body.recorded_at,
  };
}

function historyRenderIds() {
  const list = $("verification-ids");
  list.replaceChildren();
  for (const [position, id] of verification.ids.entries()) {
    const item = document.createElement("li");
    const choice = document.createElement("button");
    choice.type = "button";
    choice.className = "verification-id";
    choice.textContent = "Recorded check " + (position + 1);
    choice.title = "Record identifier: " + id;
    choice.onclick = () => historySelect(id);
    item.append(choice);
    list.append(item);
  }
}

function historyRenderRecord(record) {
  const box = $("verification-result");
  box.replaceChildren();
  const label = document.createElement("p");
  label.className = "history-label";
  label.textContent = "Historical recorded result";
  const note = document.createElement("p");
  note.className = "history-note";
  note.textContent =
    "This is what the platform judged when the check was recorded. It is not the latest check, not a " +
    "live reading, and it says nothing about whether this incident is over.";
  box.append(label, note);
  const fields = document.createElement("dl");
  for (const [name, text, className] of [
    ["Verdict recorded", record.verdict, "verdict " + record.verdict],
    ["Reason recorded", record.reason, ""],
    ["Observation window", record.start + " to " + record.end, ""],
    ["Recorded at", record.recordedAt, ""],
  ]) {
    const term = document.createElement("dt");
    term.textContent = name;
    const detail = document.createElement("dd");
    detail.textContent = text;
    if (className) detail.className = className;
    fields.append(term, detail);
  }
  box.append(fields);
  const caution = document.createElement("p");
  caution.className = "history-caution";
  caution.textContent =
    "The execution status listed above stays the runner's own report. A recorded verdict beside it " +
    "changes nothing: it does not re-run the check, re-grade the record, move the execution or end " +
    "the incident.";
  box.append(caution);
}

// Which controls are disabled right now. A visible cue is not the guard — see `historyLoad` — but it is
// what stops an operator queueing two reads the panel would have to drop on the floor anyway.
function historyBusy(loading, recordLoading) {
  $("verification-load").disabled = loading;
  for (const choice of $("verification-ids").querySelectorAll("button"))
    choice.disabled = recordLoading || loading;
}

async function historyLoad() {
  // The disabled attribute is the cue; this test is the guard, so a synthetic click that raced the
  // repaint cannot spend a second request on one intent.
  if (verification.loading || !verification.execution) return;
  const mine = ++verification.generation;
  const execution = verification.execution;
  verification.loading = true;
  // A list reloaded is a record request superseded, and the flag has to go with it: leaving it set would
  // hand the panel a permanent "busy" that no answer can clear, because the answer it was waiting for is
  // now one this generation has thrown away. Everything the old read owned is emptied here, and its
  // completion is dropped by the gate below.
  verification.recordLoading = false;
  verification.ids = [];
  $("verification-ids").replaceChildren();
  $("verification-result").replaceChildren();
  recordState("");
  historyBusy(true, false);
  historyState("loading");
  const answer = await historyFetch(
    RECORDS_ROUTE + "?" + new URLSearchParams({ execution_id: execution }),
  );
  if (!historyAnswered(mine)) return;
  if (answer.answer === "session") return signout();
  verification.loading = false;
  historyBusy(false, false);
  if (answer.answer !== "ok")
    return historyState(
      answer.answer === "refused" || answer.answer === "unreachable"
        ? "unavailable"
        : answer.answer,
    );
  const ids = historyIds(answer.body);
  if (ids === null) return historyState("malformed");
  verification.ids = ids;
  if (!ids.length) return historyState("empty");
  historyRenderIds();
  historyState(
    "loaded",
    ids.length +
      " recorded verification id(s) for this execution, listed in id order. Id order is not time " +
      "order, and an id listed here says nothing about the incident now.",
  );
}

async function historySelect(id) {
  if (verification.loading || verification.recordLoading) return;
  const mine = ++verification.generation;
  const execution = verification.execution;
  verification.recordLoading = true;
  $("verification-result").replaceChildren();
  historyBusy(false, true);
  recordState("loading");
  const answer = await historyFetch(
    RECORD_ROUTE + "?" + new URLSearchParams({ verification_id: id }),
  );
  if (!historyAnswered(mine)) return;
  if (answer.answer === "session") return signout();
  verification.recordLoading = false;
  historyBusy(false, false);
  if (answer.answer !== "ok")
    return recordState(
      answer.answer === "refused" || answer.answer === "unreachable"
        ? "unavailable"
        : answer.answer,
    );
  const record = historyRecord(answer.body, id, execution);
  if (record === "mismatch") return recordState("mismatch");
  if (!record) return recordState("malformed");
  recordState("recorded");
  historyRenderRecord(record);
}

// --- Observer investigations --------------------------------------------------------------
// One page of the observer's own cycles, the retained record of one cycle, and one append per explicit
// human grade. `observer_review.py` decides every rule; this panel only echoes the digest and newest
// review id it was shown, mints a review id once per intended review (so retrying the same review is
// the same append, never a second one), and stops after a conflict until the operator reloads.
// Nothing here is a verdict: an ungraded cycle says "not reviewed", the grade boxes start untouched,
// and every retained word — a rationale, a label, an error — is data rendered as text, never markup.
const OBSERVER_LIST = "/v1/observer/cycles";
const OBSERVER_CYCLE = "/v1/observer/cycle";
const OBSERVER_FEEDBACK = "/v1/observer/feedback";
const OBSERVER_PAGE = 20; // under the route's 100 cap: a phone screen holds a page, not a journal
const OBSERVER_ROWS = 25; // evidence rows or citations listed per item, with the cut stated in words
const OBSERVER_ANSWER = 4000; // journal.feedback's own ceiling for `corrected_answer`
const OBSERVER_SECONDS = 3600; // journal.feedback's own ceiling for `review_seconds`
const REVIEW_ID_TEXT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/; // observer contract `name()`
const OBSERVER_CHOICES = { usefulness: ["useful", "noise", "unsure"], correctness: ["correct", "incorrect", "unsure"] };
const OBSERVER_LEGENDS = { usefulness: "Was this useful?", correctness: "Was the answer correct?" };
// A retained cycle status, shown in the words the platform already uses for a record. An unlisted
// status keeps its own word and the plain pill, because inventing a colour for it would be a claim.
const OBSERVER_PILLS = { completed: "resolved", partial: "pending", failed: "error",
  running: "running", skipped: "unknown" };
const OBSERVER_QUEUES = { "quiet-sample": "quiet sample", "finding-or-coverage-gap": "finding or gap" };
// The journal's own fixed refusal words. Only these may be named back — they are payload-free by that
// module's contract, so naming one echoes no path, no credential and none of the caller's bytes.
const OBSERVER_REQUEST_CODES = ["invalid_fields", "invalid_usefulness", "invalid_correctness",
  "invalid_corrected_answer", "invalid_outcome_refs", "invalid_review_seconds", "invalid_export_approval",
  "unknown_outcome_reference", "corrected_evidence_required_for_export"];
const OBSERVER_STALE_CODES = new Set(["stale_review", "cycle_digest_changed"]);
// Fixed sentences. Each is the whole answer this surface can give about one state, and a 404 is here
// "this platform has no review journal" — never a healthy-looking page of nothing.
const OBSERVER_STATES = {
  idle: "",
  loading: "Loading investigations.",
  ready: (shown, total, older) => shown + " of " + total + " retained cycles, newest first"
    + (older ? " \u2014 " + (total - shown) + " older cycle(s) available below." : "."),
  unauthorised: "This sign-in may not read investigations, so nothing is shown.",
  absent: "The observer journal has no record of this cycle, so there is nothing to grade.",
  unavailable: "Investigation review is unavailable: this platform has no observer journal configured.",
  busy: "The observer journal could not be read. Nothing was listed, and nothing was recorded.",
  malformed: "The reply was not an investigation list this panel can vouch for, so nothing is listed.",
  refused: "The platform refused this request. Nothing was listed, and nothing was recorded.",
  unreachable: "The platform could not be reached. Nothing was listed, and nothing was recorded.",
  "not-loaded": "Not loaded.",
  reading: "Reading the retained investigation.",
  reloading: "Loading this record again. What you already typed is kept.",
  empty: "No evidence was retained for this cycle.",
  answered: "The record below is what the observer retained. It is not a verdict, and nothing is "
    + "graded until you submit.",
  unreviewable: "This record cannot be graded \u2014 it is still running or left no answer. "
    + "Everything above stays readable.",
  mismatch: "The reply was about another cycle, so nothing is shown.",
  broken: "The reply was not an investigation record this panel can vouch for, so nothing is shown.",
  recorded: (reviewer) => OBSERVER_STATES.done + " Recorded by " + reviewer + ".",
  done: "Review recorded. The observer's retained record of this cycle is unchanged.",
  stale: "This review was refused: the cycle moved on, or another review became the newest. "
    + "Nothing was recorded. Reload this record before grading it again.",
  reused: "This review was refused: that review id already holds different contents. Nothing was "
    + "recorded. Reload this record before grading it again.",
  ungraded: "Refused: this cycle cannot be graded in the state the journal now holds it in. Nothing was recorded.",
  conflict: "This review was refused by the journal. Nothing was recorded. Reload this record before grading it again.",
  refusedCode: (code) => "Refused (" + code + "). Nothing was recorded.",
  unknown: "The platform's answer did not arrive, so it is not known whether this review was "
    + "recorded. Reload this record before trying again, and only send a different review after "
    + "you have seen what the record holds.",
  grade: "Choose a usefulness grade and a correctness grade. Nothing was sent.",
  seconds: "Review seconds must be a whole number from 0 to 3600. Nothing was sent.",
  answer: "A corrected answer must be at most 4000 characters. Nothing was sent.",
  changed: "This is a different review from the one whose outcome is unknown. Nothing was sent: "
    + "reload this record first.",
  sent: "A review is already being sent. Wait for it before sending another.",
};

// The list page: the rows on screen, what the route said about the rest, and the one generation every
// list answer is judged by. `readable`/`isObject`/`exactKeys` below are shared with the record panel.
const cycles = { generation: 0, loading: false, rows: [], next: null, total: 0 };

// One opened record. `digest` and `latest` are the preconditions the route demands back unchanged;
// `reviewId`/`attempt` are what make a retry of one review the same append; `blocked` is the 409 latch.
const observer = { generation: 0, cycle: "", digest: "", latest: null, reviewable: false, loading: false,
  submitting: false, blocked: false, reviewId: "", attempt: null, grades: { usefulness: [], correctness: [] } };

// One retained value, in words. An object or array reaching a field this panel expected a string in
// is shown as the JSON it is, because `String({})` would print a lie about the record.
const readable = (item) => (item === null || item === undefined ? "not recorded"
  : typeof item === "object" ? JSON.stringify(item) : String(item));
const isObject = (item) => !!item && typeof item === "object" && !Array.isArray(item);
const exactKeys = (item, keys) =>
  isObject(item) && Object.keys(item).sort().join() === keys.slice().sort().join();
const isReviewId = (item) => typeof item === "string" && REVIEW_ID_TEXT.test(item);
// One retained word, in the words this panel is allowed to use for it. Anything the panel does not
// have a name for is shown as the journal wrote it, never guessed at.
const word = (item) => OBSERVER_QUEUES[item] || readable(item);

async function observerRequest(path, body) {
  // Same-origin, `no-store`, credential in the header alone and never in the path. The status is kept:
  // a 403, 404, 409 and 503 are four different facts for the person holding the phone.
  try {
    const response = await fetch(path, {
      method: body ? "POST" : "GET",
      cache: "no-store",
      headers: {
        Authorization: (authMode === "password" ? "Basic " : "Bearer ") + token,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (response.status === 401) return { answer: "session", status: 401 };
    let parsed;
    try {
      parsed = await response.json();
    } catch {
      return { answer: "unreadable", status: response.status };
    }
    return { answer: response.ok ? "ok" : "refused", status: response.status, body: parsed };
  } catch {
    return { answer: "unreachable" };
  }
}

// One answer, one sentence. A read that came back refused is judged by status alone; the body of a
// refusal never reaches the screen, because the only words this panel repeats are its own.
function readState(answer, forbidden, refused) {
  if (answer.answer === "unreachable") return "unreachable";
  if (answer.answer === "unreadable") return "malformed";
  if (answer.status === 403) return "unauthorised";
  if (answer.status === 404) return forbidden;
  // 503 is the journal itself refusing, which is a different fact from a request this panel got wrong,
  // and the two sentences say different things about what the operator can do next.
  return answer.status === 503 ? "busy" : refused;
}

function listState(code, text) {
  const line = $("observer-summary");
  line.dataset.state = code;
  line.textContent = text === undefined ? OBSERVER_STATES[code] : text;
  line.hidden = !line.textContent;
  $("observer-more").hidden = code !== "ready" || !cycles.next;
}

function cyclesClear() {
  cycles.generation++;
  cycles.loading = false;
  cycles.rows = [];
  cycles.next = null;
  cycles.total = 0;
  // An answer dropped by the generation guard returns early and never reaches the flags it would have
  // cleared, so anything a wipe of the list owns has to be restored here: a signed-out or switched-away
  // panel that can never be refreshed again is the bug this line exists to prevent.
  $("refresh").disabled = false;
  $("observer-next").disabled = false;
  $("observer-more").hidden = true;
  listState("idle");
}

// The five tests a list answer must pass before it may touch the screen: still the request this panel
// is waiting for, still the sign-in that made it, still inside the same login, still signed in, and
// still on the view that asked. A dropped answer performs no side effect at all.
function cyclesCurrent(mine, session, login) {
  return mine === cycles.generation && session === token && login === generation && !!token
    && view === "investigations";
}

async function refreshCycles(older) {
  if (cycles.loading) return;
  const after = older ? cycles.next : null;
  if (older && !after) return;
  const mine = ++cycles.generation;
  const session = token, login = generation;
  cycles.loading = true;
  $("refresh").disabled = true;
  $("observer-next").disabled = true;
  $("error").hidden = true;
  if (!after) listState("loading");
  const page_query = OBSERVER_LIST + "?limit=" + OBSERVER_PAGE + (after ? "&after=" + after : "");
  const answer = await observerRequest(page_query);
  if (!cyclesCurrent(mine, session, login)) return;
  cycles.loading = false;
  $("refresh").disabled = false;
  $("observer-next").disabled = false;
  if (answer.answer === "session") return signout();
  const page = answer.answer === "ok" ? reviewPage(answer.body) : null;
  const failed = answer.answer !== "ok" ? readState(answer, "unavailable", "refused")
    : page === null ? "malformed" : null;
  if (failed) {
    if (!older) { cycles.rows = []; cycles.next = null; cycles.total = 0; render(); }
    return listState(failed);
  }
  cycles.rows = older ? cycles.rows.concat(page.cycles) : page.cycles;
  cycles.next = page.truncated ? page.next_after : null;
  cycles.total = page.total_cycles;
  render();
  listState("ready", OBSERVER_STATES.ready(cycles.rows.length, cycles.total, Boolean(cycles.next)));
}

// A list page this panel can account for, or nothing at all: the seven keys the route names, a row for
// every count it gives, and every identifier in the journal's own shape. One field out of place is a
// refusal, never a shorter list to show anyway.
function reviewPage(body) {
  const keys = ["schema_version", "cycles", "limit", "returned", "total_cycles", "truncated", "next_after"];
  if (!exactKeys(body, keys) || body.schema_version !== 1 || !Array.isArray(body.cycles)) return null;
  if (!Number.isInteger(body.limit) || !Number.isInteger(body.returned)
      || !Number.isInteger(body.total_cycles)) return null;
  if (typeof body.truncated !== "boolean" || body.returned !== body.cycles.length) return null;
  if (body.total_cycles < body.returned) return null;
  if (body.next_after !== null && !isReviewId(body.next_after)) return null;
  if (body.truncated && body.next_after === null) return null;
  return body.cycles.every(reviewSummary) ? body : null;
}

function reviewSummary(row) {
  const keys = ["cycle_id", "started_at", "ended_at", "status", "coverage", "decision", "mode",
    "delivery_status", "review", "reviewable", "findings", "queue_reason", "latest_feedback_id"];
  if (!exactKeys(row, keys) || !isReviewId(row.cycle_id)) return false;
  if (!["status", "coverage", "mode", "delivery_status"].every((key) => typeof row[key] === "string")) return false;
  if (["quiet", "watch", "tell", null].indexOf(row.decision) < 0) return false;  // the route's own set
  if (["unknown", "reviewed"].indexOf(row.review) < 0 || typeof row.reviewable !== "boolean") return false;
  if (!Number.isInteger(row.findings) || row.findings < 0) return false;
  if (row.queue_reason !== null && !(row.queue_reason in OBSERVER_QUEUES)) return false;
  if (row.latest_feedback_id !== null && !isReviewId(row.latest_feedback_id)) return false;
  return [row.started_at, row.ended_at].every((item) => item === null || typeof item === "string");
}

function renderCycles() {
  const search = $("search").value.toLowerCase().trim();
  const filtered = cycles.rows.filter((row) =>
    !search || [row.cycle_id, row.status, row.coverage, row.decision, row.review, row.queue_reason]
      .map(readable).join(" ").toLowerCase().includes(search));
  const head = document.createElement("tr");
  for (const label of ["Cycle", "Outcome", "Human grade", ""]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  $("columns").replaceChildren(head);
  $("records").replaceChildren();
  $("empty").hidden = filtered.length !== 0;
  $("empty").textContent = filtered.length ? "" : token
    ? search ? "No listed cycle matches this search." : "No investigations are listed."
    : "Sign in to view records.";
  for (const row of filtered) {
    const grade = row.review === "reviewed" ? "reviewed" : "not reviewed";
    const note = row.queue_reason ? word(row.queue_reason)
      : row.reviewable ? "" : "cannot be graded yet";
    const tr = document.createElement("tr");
    [[row.cycle_id, ""], [[row.decision, row.coverage, row.status].map(word).join(" / "),
        "pill " + (OBSERVER_PILLS[row.status] || "")],
      [grade + (note ? " (" + note + ")" : ""), "pill " + (row.review === "reviewed" ? "resolved" : "pending")]]
      .forEach(([text, className]) => {
        const td = document.createElement("td");
        td.textContent = text;
        td.title = text;
        if (className) td.className = className;
        tr.append(td);
      });
    const action = document.createElement("td");
    action.append(button("Inspect investigation", "chevron-right", () => inspectCycle(row)));
    tr.append(action);
    $("records").append(tr);
  }
  icons();
}

function reviewState(code, text) {
  const line = $("observer-state");
  line.dataset.state = code;
  line.textContent = text === undefined ? OBSERVER_STATES[code] : text;
}

function reviewFeedback(code, text) {
  const line = $("observer-feedback");
  line.dataset.state = code;
  line.textContent = text === undefined ? OBSERVER_STATES[code] : text;
  line.hidden = !line.textContent;
}

// Wipes everything this panel put in the dialog, in-flight flags included: an answer on its way to a
// closed dialog has nowhere to land, and a reopened record starts again with untouched grade boxes.
function reviewClear() {
  observer.generation++;
  observer.cycle = "";
  observer.digest = "";
  observer.latest = null;
  observer.reviewable = false;
  observer.loading = false;
  observer.submitting = false;
  observer.blocked = false;
  observer.reviewId = "";
  observer.attempt = null;
  observer.grades = { usefulness: [], correctness: [] };
  $("observer").hidden = true;
  $("observer-review").hidden = true;
  $("observer-record").replaceChildren();
  $("observer-history").replaceChildren();
  $("observer-grades").replaceChildren();
  $("observer-answer").value = "";
  $("observer-seconds").value = "";
  $("observer-export").checked = false;
  reviewFeedback("idle");
  reviewControls(false);
  reviewState("not-loaded");
}

// Which controls are shut right now. A shut button is the cue, not the guard: `reviewSubmit` and
// `cyclesCurrent`/`observerCurrent` are what actually drop a request.
function reviewControls(enabled) {
  for (const group of ["usefulness", "correctness"])
    for (const input of observer.grades[group]) input.disabled = !enabled;
  for (const id of ["observer-answer", "observer-seconds", "observer-export"]) $(id).disabled = !enabled;
  reviewReady();
}

// The two grades as the journal wants them, or null. A group with nothing checked, or with something
// checked that is not one of the three words the route accepts, reads as no grade at all.
function reviewPicked() {
  const one = (group) => {
    const chosen = observer.grades[group].filter((input) => input.checked);
    return chosen.length === 1 && OBSERVER_CHOICES[group].indexOf(chosen[0].value) >= 0 ? chosen[0].value : null;
  };
  return { usefulness: one("usefulness"), correctness: one("correctness") };
}

function reviewArmed() {
  const picked = reviewPicked();
  return observer.reviewable && !observer.loading && !observer.submitting && !observer.blocked
    && !!picked.usefulness && !!picked.correctness;
}

function reviewReady() {
  $("observer-submit").disabled = !reviewArmed();
}

// Built fresh for every record, so no earlier answer can survive into a later cycle: two untouched
// radio groups whose only values are the journal's own words. No `checked` attribute is ever set here,
// because an untouched form that reads as `useful`/`correct` would be a grade nobody gave.
function reviewFields() {
  const box = $("observer-grades");
  box.replaceChildren();
  observer.grades = { usefulness: [], correctness: [] };
  for (const group of ["usefulness", "correctness"]) {
    const field = document.createElement("fieldset");
    field.className = "observer-grades";
    const legend = document.createElement("legend");
    legend.textContent = OBSERVER_LEGENDS[group];
    field.append(legend);
    for (const choice of OBSERVER_CHOICES[group]) {
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.type = "radio";
      input.name = "observer-" + group;
      input.value = choice;
      input.onclick = reviewReady;
      label.append(input, document.createTextNode(" " + choice));
      field.append(label);
      observer.grades[group].push(input);
    }
    box.append(field);
  }
}

// The five tests a record answer must pass: still the request this panel waits for, still the sign-in
// that made it, still inside the same login, still the record the operator opened, and still in a
// dialog that is open. The last is not redundant with the counter — `close()` clears `open` before its
// `close` event runs — so an answer landing in that gap has nowhere to write.
function observerCurrent(mine, session, login, cycleId) {
  return mine === observer.generation && session === token && login === generation && !!token
    && cycleId === observer.cycle && $("detail").open;
}

function inspectCycle(row) {
  detailGeneration++;
  reviewClear();
  historyClear();
  const mine = observer.generation;
  $("detail-title").textContent = "Investigation " + row.cycle_id;
  $("detail-fields").replaceChildren();
  $("commands").replaceChildren();
  $("evidence").replaceChildren();
  $("detail-error").textContent = "";
  $("observer").hidden = false;
  icons();
  $("detail").showModal();
  if (!isReviewId(row.cycle_id)) return reviewState("broken"); // not a cycle any route could name
  observer.cycle = row.cycle_id;
  loadRecord(row.cycle_id, mine, false);
}

function loadRecord(cycleId, mine, keepAnswers, keepMessage) {
  const session = token, login = generation;
  observer.loading = true;
  observer.submitting = false;
  observer.blocked = false;
  reviewControls(false);
  if (!keepAnswers) {
    $("observer-answer").value = "";
    $("observer-seconds").value = "";
    $("observer-export").checked = false;
  }
  // What the panel last told the operator is theirs, not the record's: a reload under a refusal or a
  // receipt keeps that line, because losing it would leave the screen claiming nothing about an action
  // that was just taken in front of them.
  if (!keepAnswers && !keepMessage) reviewFeedback("idle");
  reviewState(keepAnswers ? "reloading" : "reading");
  $("observer-reload").disabled = true;
  observerRequest(OBSERVER_CYCLE + "?cycle_id=" + cycleId).then((answer) => {
    if (!observerCurrent(mine, session, login, cycleId)) return;
    observer.loading = false;
    if (answer.answer === "session") return signout();
    $("observer-reload").disabled = false; // whatever the answer was, reading the record again is the
    // next thing an operator can do, and the only one this panel can offer after a failure
    if (answer.answer !== "ok") return reviewState(readState(answer, "absent", "refused"));
    const record = reviewRecord(answer.body, cycleId);
    if (record === "mismatch") return reviewState("mismatch");
    if (!record) return reviewState("broken");
    renderRecord(record);
  });
}

// One record, or nothing shown. The digest and newest review id are the two values a submission has to
// answer back, so both are checked in the journal's own shape; the review versions must belong to this
// cycle, and `latest_feedback_id` must name the last of them. A reply that fails any of that is a
// refusal, not a record to render with holes.
function reviewRecord(body, cycleId) {
  const keys = ["schema_version", "cycle_sha256", "reviewable", "latest_feedback_id", "feedback_total",
    "feedback_truncated", "replay"];
  if (!exactKeys(body, keys) || body.schema_version !== 1) return null;
  if (!isDigest(body.cycle_sha256) || typeof body.reviewable !== "boolean") return null;
  if (!Number.isInteger(body.feedback_total) || body.feedback_total < 0) return null;
  if (typeof body.feedback_truncated !== "boolean") return null;
  if (body.latest_feedback_id !== null && !isReviewId(body.latest_feedback_id)) return null;
  const replay = body.replay;
  if (!isObject(replay) || replay.cycle_id !== cycleId) return "mismatch";
  if (!["status", "coverage", "mode"].every((key) => typeof replay[key] === "string")) return null;
  if (["unknown", "reviewed"].indexOf(replay.review) < 0) return null;
  if (!Array.isArray(replay.evidence) || !Array.isArray(replay.feedback)) return null;
  if (replay.feedback.length > body.feedback_total) return null;
  if (!replay.feedback.every((item) => isObject(item) && isReviewId(item.feedback_id)
      && item.cycle_id === cycleId)) return null;
  const last = replay.feedback[replay.feedback.length - 1];
  if (body.latest_feedback_id !== null
      && (replay.feedback.length === 0 || last.feedback_id !== body.latest_feedback_id)) return null;
  return { cycle: cycleId, digest: body.cycle_sha256, reviewable: body.reviewable, latest: body.latest_feedback_id,
    total: body.feedback_total, truncated: body.feedback_truncated, replay };
}

function heading(text) {
  const title = document.createElement("h4");
  title.textContent = text;
  return title;
}

function plain(text, className) {
  const line = document.createElement("p");
  line.textContent = text;
  if (className) line.className = className;
  return line;
}

function facts(target, entries) {
  const list = document.createElement("dl");
  for (const [name, text] of entries) {
    const term = document.createElement("dt");
    term.textContent = name;
    const detail = document.createElement("dd");
    detail.textContent = text;
    list.append(term, detail);
  }
  target.append(list);
  return list;
}

// Retained data, rendered as data. `labels` is a nested object or array and `rationale` is model prose
// that may hold shell metacharacters or markup-looking bytes: both go through `textContent`, so what an
// operator reads is exactly what the journal kept and nothing becomes a node.
function renderRecord(record) {
  const replay = record.replay;
  const box = $("observer-record");
  box.replaceChildren();
  facts(box, [
    ["Cycle", record.cycle], ["Status", readable(replay.status)], ["Coverage", readable(replay.coverage)],
    ["Decision", readable(replay.decision)], ["Mode", readable(replay.mode)],
    ["Delivery", isObject(replay.delivery) ? readable(replay.delivery.status) : "not recorded"],
    ["Started", readable(replay.started_at)], ["Ended", readable(replay.ended_at)],
    ["Interruption", readable(replay.error)],
    ["Findings", String(Array.isArray(replay.answer?.findings) ? replay.answer.findings.length : 0)],
    ["Human grade", replay.review === "reviewed" ? "reviewed" : "not reviewed"],
    ["Reviews held", String(record.total)],
  ]);
  box.append(heading("What the observer said"));
  if (!isObject(replay.answer)) box.append(plain("no answer was retained for this cycle", "observer-none"));
  else {
    facts(box, [["Rationale", readable(replay.answer.rationale)]]);
    const citations = Array.isArray(replay.answer.citations) ? replay.answer.citations : [];
    box.append(plain("Citations: " + citations.length, "observer-none"));
    for (const citation of citations.slice(0, OBSERVER_ROWS)) box.append(plain(JSON.stringify(citation, null, 2)));
    if (citations.length > OBSERVER_ROWS) box.append(plain(
      citations.length - OBSERVER_ROWS + " more citation(s) retained, not listed.", "observer-none"));
  }
  box.append(heading("Evidence (" + replay.evidence.length + ")"));
  if (!replay.evidence.length) box.append(plain(OBSERVER_STATES.empty, "observer-none"));
  for (const [index, item] of replay.evidence.entries()) {
    const rows = Array.isArray(item?.rows) ? item.rows : [];
    const block = document.createElement("details");
    const title = document.createElement("summary");
    title.textContent = "Evidence " + (index + 1) + " \u00b7 " + readable(item?.source) + " \u00b7 "
      + rows.length + " row(s)";
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(
      isObject(item) ? { ...item, rows: rows.slice(0, OBSERVER_ROWS) } : {}, null, 2)
      + (rows.length > OBSERVER_ROWS
        ? "\n\u2026 " + (rows.length - OBSERVER_ROWS) + " more row(s) retained, not listed." : "");
    block.append(title, pre);
    box.append(block);
  }
  renderHistory(record);
  const reviewable = record.reviewable && role === "human";
  observer.digest = record.digest;
  observer.latest = record.latest;
  observer.reviewable = reviewable;
  observer.reviewId = "";
  observer.attempt = null;
  $("observer-review").hidden = !reviewable;
  if (reviewable) reviewFields();
  reviewControls(reviewable);
  reviewState(reviewable ? "answered" : record.reviewable ? "unauthorised" : "unreviewable");
}

function renderHistory(record) {
  const box = $("observer-history");
  box.replaceChildren();
  box.append(heading("Review history"));
  const reviews = record.replay.feedback.slice().reverse(); // newest first: the one question a reader asks
  box.append(plain(record.total + " review(s) held" + (record.truncated
    ? " \u2014 the newest " + reviews.length + " are listed; older ones stay in the journal." : "."), "observer-none"));
  reviews.forEach((item, index) => {
    box.append(plain(index === 0 && record.latest === item.feedback_id
      ? "Latest review" : "Earlier review", "history-label"));
    facts(box, [["By", readable(item.reviewer)], ["Recorded", readable(item.recorded_at)],
      ["Usefulness", readable(item.usefulness)], ["Correctness", readable(item.correctness)],
      ["Corrected answer", item.corrected_answer ? String(item.corrected_answer) : "none"],
      ["Export approved", item.export_approved ? "yes" : "no"],
      ["Review seconds", readable(item.review_seconds)], ["Review id", readable(item.feedback_id)]]);
  });
}

// The identity of the review a retry must reproduce: cycle, digest, newest review and the answer. The
// `feedback_id` is deliberately not part of it, and object key order is normalised so the same review
// written the same way is one key. Changed bytes are a different review, and this panel never sends one
// without a human choosing it.
function reviewAttemptKey(cycleId, values) {
  const stable = (item) => (Array.isArray(item)
    ? item.map(stable)
    : isObject(item) ? Object.fromEntries(Object.keys(item).sort().map((key) => [key, stable(item[key])])) : item);
  return JSON.stringify(stable({ cycle_id: cycleId, cycle_sha256: observer.digest,
    previous_feedback_id: observer.latest, values }));
}

function newReviewId() {
  return "review-" + Array.from(crypto.getRandomValues(new Uint8Array(16)),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function reviewSubmit() {
  if (!reviewArmed())
    return reviewFeedback(observer.submitting ? "sent" : Object.values(reviewPicked()).some((item) => !item)
      ? "grade" : observer.blocked ? "stale" : "unreviewable");
  const picked = reviewPicked();
  const corrected = $("observer-answer").value;
  if (corrected.length > OBSERVER_ANSWER) return reviewFeedback("answer");
  const seconds = $("observer-seconds").value;
  if (seconds !== "" && (!/^(0|[1-9][0-9]*)$/.test(seconds) || Number(seconds) > OBSERVER_SECONDS))
    return reviewFeedback("seconds");
  const values = { usefulness: picked.usefulness, correctness: picked.correctness,
    corrected_answer: corrected === "" ? null : corrected,
    export_approved: $("observer-export").checked === true,
    review_seconds: seconds === "" ? null : Number(seconds) };
  // `settled` means the journal answered in a way that proves nothing was appended, so the operator may
  // fix the form and send a different review. `unknown` means it cannot be known, so a different review
  // waits until the record has been read again; the identical one keeps the same id and is idempotent.
  const key = reviewAttemptKey(observer.cycle, values);
  if (observer.attempt && observer.attempt.key !== key && observer.attempt.outcome === "unknown")
    return reviewFeedback("changed");
  if (!observer.reviewId || (observer.attempt && observer.attempt.key !== key)) observer.reviewId = newReviewId();
  observer.attempt = { key, outcome: "unknown" };
  const body = { cycle_id: observer.cycle, feedback_id: observer.reviewId, cycle_sha256: observer.digest,
    previous_feedback_id: observer.latest, values };
  const cycleId = observer.cycle, mine = ++observer.generation;
  const session = token, login = generation;
  observer.submitting = true;
  observer.loading = false;
  reviewControls(false);
  $("observer-reload").disabled = true;
  reviewFeedback("idle");
  const answer = await observerRequest(OBSERVER_FEEDBACK, body);
  if (!observerCurrent(mine, session, login, cycleId)) return;
  observer.submitting = false;
  if (answer.answer === "session") return signout();
  if (answer.answer === "ok") {
    const receipt = answer.body?.feedback;
    if (!isObject(answer.body) || !exactKeys(answer.body, ["schema_version", "feedback"])
        || !isObject(receipt) || receipt.feedback_id !== body.feedback_id
        || receipt.cycle_id !== cycleId || typeof receipt.reviewer !== "string") {
      reviewControls(true);
      return reviewFeedback("broken");
    }
    observer.attempt = null;
    reviewFeedback("recorded", OBSERVER_STATES.recorded(receipt.reviewer));
    loadRecord(cycleId, ++observer.generation, false, true);
    return;
  }
  if (answer.status === 409) {
    const detail = isObject(answer.body) ? answer.body.detail : null;
    observer.attempt.outcome = "settled";
    observer.blocked = true;
    reviewControls(false);
    $("observer-reload").disabled = false;
    return reviewFeedback(detail === "feedback_id_reused" ? "reused" : detail === "cycle_not_reviewable"
      ? "ungraded" : OBSERVER_STALE_CODES.has(detail) ? "stale" : "conflict");
  }
  const code = isObject(answer.body) ? answer.body.detail : null;
  if (typeof code === "string" && OBSERVER_REQUEST_CODES.indexOf(code) >= 0) {
    observer.attempt.outcome = "settled"; // refused on form, before the journal could append anything
    reviewControls(true);
    return reviewFeedback("refused", OBSERVER_STATES.refusedCode(code));
  }
  if (answer.answer === "unreachable" || answer.answer === "unreadable") {
    // Whether the append landed genuinely cannot be known from here, so the exact review stays on
    // screen with its own id: pressing Send again repeats it, which the journal answers with the
    // first receipt. Only a *different* review is refused, and only until the record is read again.
    reviewControls(true);
    return reviewFeedback("unknown");
  }
  reviewControls(true);
  return reviewFeedback(answer.status === 503 ? "busy" : "conflict");
}
function details(row) {
  detailGeneration++;
  reviewClear();
  $("detail-title").textContent = row.display?.description || titles[view].replace(/s$/, "") + " record";
  $("detail-fields").replaceChildren();
  $("commands").replaceChildren();
  $("evidence").replaceChildren();
  $("detail-error").textContent = "";
  historyClear();
  const data = payload(row);
  for (const [key, val] of Object.entries({ ...(row.display || {}), ...row, ...data })) {
    if (key === "payload" || key === "display") continue;
    const dt = document.createElement("dt");
    dt.textContent = key.replaceAll("_", " ");
    const dd = document.createElement("dd");
    dd.textContent = value(val);
    $("detail-fields").append(dt, dd);
  }
  for (const ref of data.evidence || []) {
    if (!ref.parameters?.sample_id) continue;
    const b = button("Read evidence", "file-search", async () => {
      try {
        const result = await api(
          "/v1/evidence?" +
            new URLSearchParams({
              source: ref.source,
              sample_id: ref.parameters.sample_id,
            }),
        );
        const p = document.createElement("pre");
        p.textContent = JSON.stringify(result, null, 2);
        $("evidence").replaceChildren(p);
      } catch (error) {
        $("detail-error").textContent = error.message;
      }
    });
    b.append(document.createTextNode("Read evidence"));
    $("evidence").append(b);
  }
  if (role === "human" && view === "actions" && row.status === "pending") {
    $("commands").append(
      command("Approve", "check", "/v1/actions/decision", null, () => approvalReview(row)),
      command("Deny", "x", "/v1/actions/decision", { action_id: row.id, decision: "denied" }),
    );
  }
  if (role === "human" && view === "actions" && row.status === "approved")
    $("commands").append(command("Withdraw approval", "x", "/v1/actions/decision",
      { action_id: row.id, decision: "denied" }));
  if (role === "human" && view === "executions" && row.status === "unknown") {
    for (const outcome of ["succeeded", "failed"])
      $("commands").append(
        command(
          "Reconcile as " + outcome,
          "check-check",
          "/v1/executions/outcome",
          { execution_id: row.id, outcome },
        ),
      );
  }
  if (role === "human" && view === "outbox" && row.status === "dead")
    $("commands").append(
      command("Retry delivery", "rotate-cw", "/v1/notifications/retry", {
        delivery_id: row.id,
      }),
    );
  // Executions only: a verification record is a statement about one run, and the record's own
  // `execution_id` is checked against this row's id before any of it is shown.
  if (view === "executions") historyOpen(row.id);
  icons();
  $("detail").showModal();
}
$("login").addEventListener("cancel", (event) => {
  if (!token) event.preventDefault();
});
$("login-form").onsubmit = async (event) => {
  event.preventDefault();
  if (!authMode || $("login-submit").disabled) return;
  const mine = ++generation;
  $("login-submit").disabled = true;
  try {
    if (authMode === "password") {
      const username = $("username").value;
      const password = $("password").value;
      const bytes = new TextEncoder().encode(password);
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(username)
          || /[\r\n\0]/.test(password) || bytes.length < 1 || bytes.length > 1024)
        throw new Error("Enter a valid username and password.");
      token = btoa(String.fromCharCode(...new TextEncoder().encode(username + ":" + password)));
    } else token = $("token").value;
    for (const id of ["token", "username", "password"]) $(id).value = "";
    const me = await api("/v1/me");
    if (mine !== generation) return;
    role = me.role;
    $("identity").textContent = me.identity + " / " + me.role;
    $("login-error").textContent = "";
    $("login").close();
    await loadMode();
    await refresh();
  } catch (error) {
    signout();
    $("login-error").textContent = error.message;
  } finally {
    $("login-submit").disabled = !authMode;
  }
};
async function loadAuthMode() {
  try {
    const response = await fetch("/v1/operator-auth", { cache: "no-store" });
    if (!response.ok) throw new Error();
    const mode = (await response.json()).mode;
    if (mode !== "password" && mode !== "token") throw new Error();
    authMode = mode;
    for (const id of ["username", "password", "token"]) {
      const enabled = mode === "password" ? id !== "token" : id === "token";
      $(id + "-field").hidden = !enabled;
      $(id).disabled = !enabled;
      $(id).required = enabled;
    }
    $("login-submit").disabled = false;
  } catch {
    $("login-error").textContent = "Sign-in configuration unavailable. Reload to retry.";
  }
}
document.querySelectorAll("[data-view]").forEach(
  (button) =>
    (button.onclick = () => {
      view = button.dataset.view;
      document
        .querySelectorAll("[data-view]")
        .forEach((item) => item.classList.toggle("active", item === button));
      $("view-title").textContent = titles[view];
      $("status-filter").value = "";
      $("search").value = "";
      rows = [];
      cyclesClear(); // an answer about cycles has no business landing in incidents, or the reverse
      render();
      refresh();
    }),
);
$("search").oninput = render;
$("status-filter").onchange = render;
$("refresh").onclick = refresh;
$("logout").onclick = signout;
$("close-detail").onclick = () => $("detail").close();
$("verification-load").onclick = historyLoad;
$("observer-next").onclick = () => refreshCycles(true);
$("observer-reload").onclick = () => observer.cycle && loadRecord(observer.cycle, ++observer.generation, true, true);
$("observer-submit").onclick = reviewSubmit;
// Escape and the browser's own cancel close a native dialog too, and `close` is the one event all three
// paths (button, script, Escape) end with. `open` is re-tested here so the `close()` that follows a
// command cannot clear a detail dialog that was already reopened for another record.
$("detail").addEventListener("close", () => {
  if (!$("detail").open) {
    detailGeneration++;
    if ($("confirm").open) $("confirm").close("cancel");
    historyClear();
    reviewClear(); // a review on its way to a dialog that has gone has nowhere to land, and the
    // grades of a closed record must not still be sitting in the form when the next one opens
  }
});
icons();
signout();
loadAuthMode();
