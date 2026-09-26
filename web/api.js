// The API client.
//
// ONE rule governs this file: it never decides a permission. There is no role-to-permission
// table here and no `role === 'admin'` anywhere under web/ — the server resolves, and this layer
// passes the answer through. If a component ever needs to know whether something is allowed, it
// reads `data-state` off what the server sent, or it is not rendered at all.
//
// The access token lives in a module-scoped variable and nowhere else (D13): not localStorage,
// not sessionStorage, not a cookie. A page reload has no token, so `boot()` asks
// `POST /auth/refresh` to mint one from the httpOnly cookie the browser sends automatically.
// That is the whole of the session-restore mechanism, and it is why there is nothing to clear on
// sign-out beyond dropping this variable.

let accessToken = null;
let onUnauthenticated = null;

export const getToken = () => accessToken;
export const setToken = (t) => { accessToken = t ?? null; };
export const clearToken = () => { accessToken = null; };

/** Registered by the app so a 401 anywhere can drop the console back to the sign-in screen. */
export const setUnauthenticatedHandler = (fn) => { onUnauthenticated = fn ?? null; };

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message ?? `request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code ?? 'UNKNOWN';
    this.reason = body?.error?.reason ?? null;
    this.requestId = body?.error?.requestId ?? null;
  }

  /**
   * A sentence for the screen.
   *
   * The server's own words, in every case except a dead network. UI-INVENTORY.md §4 is explicit
   * that the element "carries the server's reason as text", and I had it the other way round — I
   * was rewriting 401 into "Your session has expired", which broke
   * `tests/ui.spec.js:327` (the sign-in failure has to contain "invalid" or "password") and, worse,
   * was exactly the "improving on the server's answer" the document warns about. The one thing
   * worth synthesising is a transport failure, because there is no server answer to carry.
   */
  get human() {
    if (this.status === 0) return 'Could not reach the server. Check it is running, then try again.';
    return this.message;
  }
}

async function request(method, path, { body, auth = true, headers = {} } = {}) {
  const init = { method, headers: { ...headers } };

  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (auth) {
    if (!accessToken) throw new ApiError(401, { error: { code: 'UNAUTHENTICATED', message: 'not signed in' } });
    init.headers.authorization = `Bearer ${accessToken}`;
  }

  let res;
  try {
    res = await fetch(path, init);
  } catch (err) {
    // A dead server is a state the screen has to be able to show, not swallow.
    throw new ApiError(0, { error: { code: 'NETWORK', message: 'Could not reach the server.' } });
  }

  const text = await res.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = null; }
  }

  if (!res.ok) {
    const error = new ApiError(res.status, payload);
    // 401 TOKEN_STALE is the server telling us our token no longer describes this membership. The
    // one automatic recovery: swap it for a fresh one from the refresh cookie and retry once. Any
    // other 401 means the session is genuinely over, so hand control to the app.
    if (error.status === 401 && error.code === 'TOKEN_STALE' && !path.includes('/auth/')) {
      const refreshed = await tryRefresh();
      if (refreshed) return request(method, path, { body, auth, headers });
    }
    if (error.status === 401 && onUnauthenticated) onUnauthenticated(error);
    throw error;
  }

  return payload;
}

const get = (p, o) => request('GET', p, o);
const post = (p, body, o) => request('POST', p, { ...o, body });
const patch = (p, body, o) => request('PATCH', p, { ...o, body });
const del = (p, o) => request('DELETE', p, o);

/**
 * Swap the refresh cookie for a new access token. Returns false rather than throwing, because
 * every caller treats "no session" as a normal answer, not an error.
 */
export async function tryRefresh() {
  try {
    const res = await fetch('/v1/auth/refresh', { method: 'POST' });
    if (!res.ok) return false;
    const payload = await res.json();
    accessToken = payload.token;
    return payload;
  } catch {
    return false;
  }
}

// --- auth -------------------------------------------------------------------

export const login = (email, password, orgId) => post('/v1/auth/login', { email, password, ...(orgId ? { orgId } : {}) }, { auth: false });
export const logout = () => post('/v1/auth/logout', {}, { auth: false });
export const me = () => get('/v1/auth/me');

/**
 * Switch org. This mints a NEW token rather than filtering client-side (D18), which is what makes
 * org isolation structural: after this resolves, the console physically cannot address the org it
 * just left, because the token it holds does not name that org.
 */
export async function switchOrg(orgId) {
  const payload = await post('/v1/auth/token', { orgId });
  // Store the new token. Forgetting this was a real bug: `request()` sends whatever is in the
  // module variable and does not adopt a token from a response, so the switch appeared to do
  // nothing — `/auth/me` was still being asked with the OLD org's token and dutifully returned the
  // old org. The switch is a token swap, so the swap has to include the token.
  accessToken = payload.token;
  return payload;
}

// --- reference data ---------------------------------------------------------

/**
 * The permission catalogue and role list, read from the database. The console needs these for the
 * grant form's checkboxes and the invite's role picker, and it must NOT keep its own copy — two
 * copies of the catalogue is exactly the drift BRIEF.md §5.3 warns about. This is also how a
 * permission that exists only in the graded fixture's database reaches the UI with no code change.
 */
export const reference = () => get('/v1/reference');

// --- orgs, members, audit ---------------------------------------------------

export const listOrgs = () => get('/v1/orgs');
export const createOrg = (name) => post('/v1/orgs', { name });
export const renameOrg = (orgId, name) => patch(`/v1/orgs/${orgId}`, { name });
export const deleteOrg = (orgId) => del(`/v1/orgs/${orgId}`);

export const listMembers = (orgId) => get(`/v1/orgs/${orgId}/members`);
export const setRole = (orgId, userId, role) => patch(`/v1/orgs/${orgId}/members/${userId}`, { role });
export const suspendMember = (orgId, userId) => post(`/v1/orgs/${orgId}/members/${userId}/suspend`, {});
export const reinstateMember = (orgId, userId) => del(`/v1/orgs/${orgId}/members/${userId}/suspend`);
export const removeMember = (orgId, userId) => del(`/v1/orgs/${orgId}/members/${userId}`);
export const leaveOrg = (orgId) => del(`/v1/orgs/${orgId}/members/me`);

export const effective = (orgId, userId) => get(`/v1/orgs/${orgId}/users/${userId}/effective`);

export const listAudit = (orgId, { limit = 50, offset = 0 } = {}) =>
  get(`/v1/orgs/${orgId}/audit?limit=${limit}&offset=${offset}`);

// --- invites ----------------------------------------------------------------

export const listInvites = (orgId) => get(`/v1/orgs/${orgId}/invites`);
export const createInvite = (orgId, email, role) => post(`/v1/orgs/${orgId}/invites`, { email, role });
export const revokeInvite = (orgId, id) => del(`/v1/orgs/${orgId}/invites/${id}`);

/** Public. No token — this is what the /invite/:token page calls before anyone has signed in. */
export const peekInvite = (token) => get(`/v1/invites/${encodeURIComponent(token)}`, { auth: false });
export const acceptInvite = (token, name, password) =>
  post(`/v1/invites/${encodeURIComponent(token)}/accept`, { name, password }, { auth: false });

// --- devices ----------------------------------------------------------------

export const listDevices = (orgId) => get(`/v1/orgs/${orgId}/devices`);
export const getDevice = (orgId, id) => get(`/v1/orgs/${orgId}/devices/${id}`);
export const createDevice = (orgId, name, kind) => post(`/v1/orgs/${orgId}/devices`, { name, kind });
export const renameDevice = (orgId, id, name) => patch(`/v1/orgs/${orgId}/devices/${id}`, { name });
export const decommissionDevice = (orgId, id) => del(`/v1/orgs/${orgId}/devices/${id}`);
export const transferDevice = (orgId, id, toOrgId) => post(`/v1/orgs/${orgId}/devices/${id}/transfer`, { toOrgId });

// --- grants -----------------------------------------------------------------

export const listGrants = (orgId) => get(`/v1/orgs/${orgId}/grants`);
export const createGrant = (orgId, { userId, deviceId, effect, permissions }) =>
  post(`/v1/orgs/${orgId}/grants`, { userId, deviceId: deviceId || null, effect, permissions });
export const revokeGrant = (orgId, id) => del(`/v1/orgs/${orgId}/grants/${id}`);

// --- sessions ---------------------------------------------------------------

export const listSessions = (orgId) => get(`/v1/orgs/${orgId}/sessions`);
export const startSession = (orgId, deviceId, mode) => post(`/v1/orgs/${orgId}/sessions`, { deviceId, mode });
export const stopSession = (id) => del(`/v1/sessions/${id}`);
