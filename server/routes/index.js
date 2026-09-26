// Route registration.
//
// The router is deliberately tiny: createRouter() from ../router.js, first match wins, so the
// specific paths are registered before the parameterised ones they would otherwise be shadowed by
// (`/members/me` before `/members/:userId`).
//
// The split mirrors the API, and each file is responsible for its own table of endpoints:
//
//   auth.js      public sign-in, refresh, org switch, and the console's boot endpoint
//   orgs.js      orgs, members, effective permissions, audit
//   invites.js   invites, plus the two public invite-token routes
//   devices.js   devices, transfer, grants, and the reference data the console's forms need
//   sessions.js  sessions
//
// Two ordering constraints are load-bearing rather than cosmetic:
//
//   1. `POST /v1/orgs/:org/members/me` is registered BEFORE `DELETE /v1/orgs/:org/members/:userId`
//      would match it, because the router returns the first match and `/members/me` would
//      otherwise be read as a userId of "me" — which would 404 for a caller who is, in fact,
//      trying to leave.
//   2. Everything else is order-independent, because `assertSameOrg` is the first line of every
//      org-scoped handler rather than something the router does.

import * as auth from './auth.js';
import * as orgs from './orgs.js';
import * as invites from './invites.js';
import * as devices from './devices.js';
import * as sessions from './sessions.js';

export function registerRoutes(router, deps) {
  const { db, secret } = deps;
  void db;
  void secret;

  auth.register(router, { db, secret });
  orgs.register(router, { db, secret });
  invites.register(router, { db, secret });
  devices.register(router, { db, secret });
  sessions.register(router, { db, secret });
}
