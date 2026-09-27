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
    "No decision was sent. Refresh and check the trusted runner configuration before retrying.");
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

function details(row) {
  detailGeneration++;
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
// Escape and the browser's own cancel close a native dialog too, and `close` is the one event all three
// paths (button, script, Escape) end with. `open` is re-tested here so the `close()` that follows a
// command cannot clear a detail dialog that was already reopened for another record.
$("detail").addEventListener("close", () => {
  if (!$("detail").open) {
    detailGeneration++;
    if ($("confirm").open) $("confirm").close("cancel");
    historyClear();
  }
});
icons();
signout();
loadAuthMode();
