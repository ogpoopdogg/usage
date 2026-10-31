# E&C Usage and Security

Admin page for E&C Courier, open only to justin@ec.com. It is laid out for a phone first (nothing scrolls sideways) and also comes as an Android app that sends security alerts as phone notifications (see [Android app](#android-app)). It has two tabs:

- **API usage**: the Google Maps requests each person triggered in Route Planner and Route Watcher (from `developer/api_usage`).
- **Security**: sign-ins, failed and refused sign-ins, accounts, every change to the watched parts of the database, and alerts. It reads `security_log`, which the server code in `functions/` writes.

Open the Security tab directly with `#security` at the end of the address.

PlutoScan (its own Firebase project, `plutoscan`) has its own audit functions in `plutoscan-audit/`. They send what they log to `auditIngest` here, so PlutoScan entries show in the same lists with app `plutoscan`. See `plutoscan-audit/README.md`.

## What the Security tab shows

| Part | What's in it | Where it comes from |
| --- | --- | --- |
| Alerts | Things worth a look, with a button to mark each as seen. The **Alerts** button at the top picks which kinds send a phone notification | All the functions below |
| Sign-in activity | Every sign-in (with IP address, browser, sign-in method), failed sign-ins, accounts an app turned away, new and deleted accounts, account changes, reset emails, SMS codes | `auditBeforeSignIn`, `auditSignInReport`, `auditUserCreated`, `auditUserDeleted`, `auditUserCensus`, `auditBeforeEmail`, `auditBeforeSms`, and the time clock's `timeclockBeforeUserCreated` (sign-ups) |
| Database changes | Who changed what, when, the fields that changed, and the full record before and after | One watcher per area (list below) |
| Accounts | Every Firebase sign-in account, its sign-in methods, last sign-in and the devices it has used | `auditUserCensus` (every 30 minutes) and `auditBeforeSignIn` |
| PlutoScan | Its sign-ups, sign-ins, failed sign-ins, purchases, people turned away from the course, checkout steps and visits (in the activity list, app `plutoscan`; visits only under their own filter), its account data changes, and its accounts with paid or not (Accounts, pick PlutoScan) | `plutoscan-audit/` through `auditIngest` |
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
| 5 requests to `auditIngest` with a wrong key from one IP in 10 minutes | high |

Every alert has a kind (`type`), listed in `functions/alert-types.js`; the page and the server both read that file. In the Security tab, **Alerts** opens a list of every kind with a tick box, plus one switch for all phone notifications. Ticked kinds send a notification to the Android app (`auditAlertPush`); unticked ones still show in the tab. The ticks are saved in `security_log/notify`, so they apply to every phone. Until they are first saved, high and medium kinds notify and low ones (new device, PlutoScan purchase) don't. **Send a test notification** in the same list checks a phone end to end.

PlutoScan alerts get their kind from `plutoscan-audit`. Until that codebase is deployed again (see `plutoscan-audit/README.md`), its alerts arrive without one and count as "Any other PlutoScan alert".

### Watched parts of the database

Address lookup, staff, roles, jobs, pickup requests, companies, join codes, customer profiles, dispatch phones (`push_tokens`), RouteWatcher allowed users, settings, driver nicknames and sign-in locks, route planner (except `ui_prefs` and `notification_reads`), time clock employees, settings, punches, punch fix requests, van reports, vans, oil plan and van picks, and Garage (except its own `history`). The list is `WATCHES` in `functions/lib.js`.

Left out on purpose, because they change many times a minute and would cost more than they tell you: live driver positions and `poll_state` under `developer/dispatch_dashboard`, `developer/api_usage`, the request counter, `timeclock/audit` and `garage/history` (the apps' own logs), and developer notes (they share `developer/` with the busy dispatch data).

### Limits

- **Failed sign-ins are reported by the apps.** Firebase runs no server code when a password is wrong, so each app sends a report (see `ecReportFailedSignIn` / `reportFailedSignIn` in each app). Someone calling Firebase directly with a script skips that. Turn on Identity Platform's own logging (step 4 below) so Google Cloud keeps a record either way.
- **Which app a sign-in came from** is told by the app. Firebase doesn't tell the sign-in function which app is signing in, so after a sign-in that worked each app sends a short "signed in" report with its sign-in token, and `auditSignInReport` fills in the App column on that sign-in's row. Sign-ins from before this, from an app that hasn't been updated, or made with a script show no app.
- **Who made a database change** comes from Firebase (`authType` and `authId` on the database event). The emulator does not fill these in, so they could not be tested here; check them after deploying (step 6). If changes show "Unknown" under Changed by, the non-staff and no-sign-in alerts can't fire.
- **Blocking functions don't see accounts made in the Firebase console or with admin tools.** `auditUserCreated` and the 30-minute census catch those.
- Entries are kept 90 days and alerts a year (`auditPrune`, daily at 3:30 a.m. Central).

## Setting it up

Run these in Google Cloud Shell (https://shell.cloud.google.com), signed in as an owner of the `eandccourier-36fcc` project.

1. **Database rules.** Add the `security_log` block from `security_log.rules.json` to the database rules, next to the other top-level keys, and publish (if a `security_log` block is already there, replace that block only). Only justin@ec.com can read the log; nobody can write it except the server code, apart from marking alerts as seen, the alert notification ticks (`notify`), the phones that get them (`push_tokens`) and the test button (`push_test`).
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

## Android app

The `android/` folder wraps `index.html` as an Android app (built with [Capacitor](https://capacitorjs.com), the same way as the Dispatch app) so security alerts arrive as real phone notifications, even when the app is closed. The small status-bar icon is the Dispatch app's crown. The notification uses the phone's normal notification sound.

How a notification gets to the phone: the app saves the phone's Firebase Cloud Messaging token in `security_log/push_tokens` when you sign in. Every new alert runs `auditAlertPush`, which checks the ticks in `security_log/notify` and, if that kind is ticked, sends the alert to every saved phone. Signing out of the app removes that phone.

### One-time setup

1. **Register the app in Firebase.** Firebase console, project `eandccourier-36fcc`, gear icon, Project settings, General, Your apps, **Add app**, Android. Package name **`com.eandc.usage`** (it must match exactly), nickname `E&C Usage`, leave SHA-1 empty. Download **google-services.json**.
2. **Give the file to the build**, one of two ways: upload it to this repo at `android/app/google-services.json` (on GitHub: open `android/app`, Add file, Upload files; it holds the same kind of public project ID and API key as `index.html`), or keep it out of the repo by adding a repository secret named `GOOGLE_SERVICES_JSON` (Settings, Secrets and variables, Actions) with the whole file as its value.
3. **Database rules and functions**: steps 1 and 3 of *Setting it up* above. `auditAlertPush` and `auditTestPush` are part of the `audit` codebase, so the usual deploy command adds them.
4. **(Recommended) Signing key**, so a new build installs over the old one instead of needing an uninstall first. Add four repository secrets to *this* repo: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. If you already made a key for the Dispatch app (see its `APP-SETUP.md`, step 5), the same key and values can be used here; secrets aren't shared between repos, so add them again. Without them, GitHub builds a debug APK.

### Getting it onto the phone

Every push to GitHub builds the app (Actions tab, *Build Android app*). For an easy download on the phone: Actions, *Build Android app*, *Run workflow*, tick **Also publish the APK as a GitHub Release**, *Run workflow*; then open the repo's Releases page on the phone and tap the `.apk`. Android asks to allow installs from the browser; allow it.

On first launch: sign in, tap **Allow** when Android asks about notifications, then Security, **Alerts**, **Send a test notification**. If alerts come late while the phone is idle: phone Settings, Apps, E&C Usage, Battery, **Unrestricted**.

### Changing things later

- Edit `index.html` / `security.js` as before; the website updates as usual, and the next GitHub build puts the change into the APK.
- Launcher icon and splash screen: `python3 scripts/make-android-assets.py` (from `icon-512.png`).
- Building on a computer (Node 22 and Android Studio): `npm install && npm run sync && npm run open:android`.

## Daily backup

`auditBackup` saves a copy of the whole database and its rules every evening at 7:00 PM (Brandon time) into the bucket `eandccourier-36fcc-default-rtdb-backups`, under `daily/`, as `<time>_data.json.gz` and `<time>_rules.json.gz`. It was added because Firebase's own automated backups (Realtime Database, Backups tab) got stuck on 2026-10-28. It runs alongside them and can be removed once they work again. The bucket deletes files after 30 days, like Firebase's backups. A failed backup raises a high alert ("Daily database backup failed"), which notifies the phone app.

One-time setup, in Cloud Shell:

1. **Let the function write to the bucket.** The bucket only lets Firebase's backup service write to it, so give the functions' service account permission to add files (it can't delete or overwrite them):
   ```
   PN=$(gcloud projects describe eandccourier-36fcc --format='value(projectNumber)')
   gcloud storage buckets add-iam-policy-binding gs://eandccourier-36fcc-default-rtdb-backups --member="serviceAccount:${PN}-compute@developer.gserviceaccount.com" --role=roles/storage.objectCreator
   ```
2. **Deploy only this function** (deploying the whole codebase at once has hit rate limits before):
   ```
   npx firebase-tools deploy --only functions:audit:auditBackup --project eandccourier-36fcc
   ```
3. **Run it once now and check the files:**
   ```
   gcloud scheduler jobs run firebase-schedule-auditBackup-us-central1 --location=us-central1
   sleep 60; gsutil ls -l gs://eandccourier-36fcc-default-rtdb-backups/daily/
   ```
   If the job name is different, `gcloud scheduler jobs list --location=us-central1` shows it.

To restore, download a `_data.json.gz` file, unzip it, and import it in the Firebase console (Realtime Database, Data, the three-dot menu, Import JSON). Importing replaces the data at that spot, so export the current data first.

## Running cost

Phone notifications run one short function per alert (`auditAlertPush`), and sending through Firebase Cloud Messaging is free. Each watched change runs one function, so busy areas (time clock punches, jobs) cost the most. The line under the range buttons shows how many times the watchers ran on the latest day, and `security_log/stats` keeps a count per watcher per day. Compare with the Cloud Functions line in the Firebase usage and billing page. Every function is set to 256 MiB of memory to keep each run cheap.

## Tests

```
cd functions && npm test
```

The tests cover the pure parts in `functions/lib.js` and `functions/alert-types.js`: report checking, sign-in and change entries, field differences, alerts and their kinds, which alerts notify, and the account census.

The functions were also run end to end in the Firebase emulators (auth, database, functions) with the page signed in as the admin: sign-ups, sign-ins, wrong passwords, a refused account, staff edits to the address lookup, a server-side mass delete, alerts, marking alerts seen, and the page on desktop and phone widths. The emulator sends every blocking event to one function, so `auditBeforeEmail` and `auditBeforeSms` were left out of that run.
