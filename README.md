# E&C Usage and Security

Admin page for E&C Courier, open only to justin@ec.com. It has two tabs:

- **Google API usage**: the Google Maps requests each person triggered in Route Planner and Route Watcher (from `developer/api_usage`).
- **Security**: sign-ins, failed and refused sign-ins, accounts, every change to the watched parts of the database, and alerts. It reads `security_log`, which the server code in `functions/` writes.

Open the Security tab directly with `#security` at the end of the address.

## What the Security tab shows

| Part | What's in it | Where it comes from |
| --- | --- | --- |
| Alerts | Things worth a look, with a button to mark each as seen | All the functions below |
| Sign-in activity | Every sign-in (with IP address, browser, sign-in method), failed sign-ins, accounts an app turned away, new and deleted accounts, account changes, reset emails, SMS codes | `auditBeforeSignIn`, `auditSignInReport`, `auditUserCreated`, `auditUserDeleted`, `auditUserCensus`, `auditBeforeEmail`, `auditBeforeSms`, and the time clock's `timeclockBeforeUserCreated` (sign-ups) |
| Database changes | Who changed what, when, the fields that changed, and the full record before and after | One watcher per area (list below) |
| Accounts | Every Firebase sign-in account, its sign-in methods, last sign-in and the devices it has used | `auditUserCensus` (every 30 minutes) and `auditBeforeSignIn` |
| Top lists | Failed sign-ins by email and by IP, and who changes the database most | Worked out on the page |

### Alerts

| Alert | Level |
| --- | --- |
| 5 failed sign-ins for one email in 15 minutes | high for @ec.com, medium for others |
| 5 failed sign-ins from one IP in 15 minutes (and again at 20) | medium, then high |
| A signed-in account was turned away by an app (token checked by the server) | medium |
| Any change to the staff list, roles, RouteWatcher allowed users or time clock employees | high |
| Any change to RouteWatcher settings or time clock settings | medium |
| A database change with nobody signed in | high |
| A non-staff account changed staff-only data (address lookup, jobs, route planner, RouteWatcher) | high |
| One delete that removes 20 or more values | high |
| 10 deletes by one account (or by the server/console) within 5 minutes | high |
| A new @ec.com account; an account deleted | medium; high for @ec.com, low for others |
| An account changed outside the apps: email, custom claims (high); disabled, sign-in methods, password reset, verified (medium for staff) | high / medium |
| A staff account signs in from a new kind of device | low |
| One IP sending more than 60 reports in 10 minutes (the rest are dropped) | medium |

### Watched parts of the database

Address lookup, staff, roles, jobs, pickup requests, companies, join codes, customer profiles, dispatch phones (`push_tokens`), RouteWatcher allowed users, settings, driver nicknames and sign-in locks, route planner (except `ui_prefs` and `notification_reads`), time clock employees, settings, punches, punch fix requests, van reports, vans, oil plan and van picks, and Garage (except its own `history`). The list is `WATCHES` in `functions/lib.js`.

Left out on purpose, because they change many times a minute and would cost more than they tell you: live driver positions and `poll_state` under `developer/dispatch_dashboard`, `developer/api_usage`, the request counter, `timeclock/audit` and `garage/history` (the apps' own logs), and developer notes (they share `developer/` with the busy dispatch data).

### Limits

- **Failed sign-ins are reported by the apps.** Firebase runs no server code when a password is wrong, so each app sends a report (see `ecReportFailedSignIn` / `reportFailedSignIn` in each app). Someone calling Firebase directly with a script skips that. Turn on Identity Platform's own logging (step 4 below) so Google Cloud keeps a record either way.
- **Who made a database change** comes from Firebase (`authType` and `authId` on the database event). The emulator does not fill these in, so they could not be tested here; check them after deploying (step 6). If changes show "Unknown" under Changed by, the non-staff and no-sign-in alerts can't fire.
- **Blocking functions don't see accounts made in the Firebase console or with admin tools.** `auditUserCreated` and the 30-minute census catch those.
- Entries are kept 90 days and alerts a year (`auditPrune`, daily at 3:30 a.m. Central).

## Setting it up

Run these in Google Cloud Shell (https://shell.cloud.google.com), signed in as an owner of the `eandccourier-36fcc` project.

1. **Database rules.** Add the `security_log` block from `security_log.rules.json` to the database rules, next to the other top-level keys, and publish. Only justin@ec.com can read the log; nobody can write it except the server code, apart from marking alerts as seen.
2. **Check for an existing sign-in function.** In the Firebase console, open Authentication, then Settings, then Blocking functions. A project can have only one "Before sign in" function. If one is already set (and it isn't `auditBeforeSignIn`), stop and ask before deploying, because deploying replaces it. The time clock's `timeclockBeforeUserCreated` is a "Before account creation" function and is not affected.
3. **Deploy the functions.**
   ```
   git clone https://github.com/ogpoopdogg/usage.git
   cd usage/functions && npm ci && cd ..
   npx firebase-tools deploy --only functions:audit --project eandccourier-36fcc
   ```
   This is its own codebase (`audit` in `firebase.json`), so it leaves the time clock's and the dispatch app's functions alone. The first deploy may ask to turn on a few Google Cloud APIs (Cloud Scheduler, Eventarc); say yes.
4. **Turn on Identity Platform logging.** In the Google Cloud console, open Identity Platform, then Settings, and turn on logging for user activity (the wording in the console may differ slightly). It is off by default. Logs then appear in Logs Explorer under `identitytoolkit.googleapis.com`. See https://cloud.google.com/identity-platform/docs/activity-logging.
5. **Check the report address.** Open https://us-central1-eandccourier-36fcc.cloudfunctions.net/auditSignInReport in a browser. A blank page means it's live (it only answers the apps' reports); a "not found" error means the deploy didn't finish. The apps already send to this address. Then type a wrong password into any app and refresh the Security tab.
6. **Check who-changed-what.** Edit something in the address lookup, then look at Database changes. Changed by should show the email of the person who made the change.

## Running cost

Each watched change runs one function, so busy areas (time clock punches, jobs) cost the most. The line under the range buttons shows how many times the watchers ran on the latest day, and `security_log/stats` keeps a count per watcher per day. Compare with the Cloud Functions line in the Firebase usage and billing page. Every function is set to 256 MiB of memory to keep each run cheap.

## Tests

```
cd functions && npm test
```

The tests cover the pure parts in `functions/lib.js`: report checking, sign-in and change entries, field differences, alerts and the account census.

The functions were also run end to end in the Firebase emulators (auth, database, functions) with the page signed in as the admin: sign-ups, sign-ins, wrong passwords, a refused account, staff edits to the address lookup, a server-side mass delete, alerts, marking alerts seen, and the page on desktop and phone widths. The emulator sends every blocking event to one function, so `auditBeforeEmail` and `auditBeforeSms` were left out of that run.
