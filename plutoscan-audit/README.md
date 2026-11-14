# PlutoScan security log

Server code for the `plutoscan` Firebase project. It logs what happens on plutoscan.com and sends each entry to `auditIngest` in the E&C project, so PlutoScan shows in the Security tab of the usage page next to the E&C apps (app name `plutoscan`). A copy stays in the plutoscan database under `security_log` as a backup.

It is its own codebase (`audit` in `firebase.json`), so deploying it never touches `createCheckoutSession`, `getModuleContent` or `stripeWebhook`.

## What it logs

| What | Function | Shows as |
| --- | --- | --- |
| New accounts, with IP address, browser and sign-in method (password or Google) | `auditPlutoSignUp`, `auditPlutoUserCreated` | Sign-up, Account created |
| Every sign-in that worked | `auditPlutoSignIn` | Signed in |
| Password reset emails | `auditPlutoEmail` | Email sent |
| Accounts deleted, or changed outside the site (email, disabled, claims, password reset) | `auditPlutoUserDeleted`, `auditPlutoCensus` | Account deleted, Account changed |
| Purchases: `users/{uid}/paid` turning on, and paid access removed | `auditPlutoUsers` | Purchase, alert "New purchase" |
| Every write to `users/{uid}` (progress, review, paid), who made it and what changed | `auditPlutoUsers` | Database changes, area "PlutoScan: …" |
| Every account with paid or not, created, last sign-in (every 30 minutes) | `auditPlutoCensus` | `security_log/ext/plutoscan/census` in the E&C database |
| Failed sign-ins, the course page turning someone away, checkout steps, page visits | `auditPlutoReport` (sent by plutoscan.com) | Failed sign-in, Turned away from course, Checkout, Visit |
| Inside Stripe: payments, failed card payments (with the decline reason), checkouts left unfinished, refunds, chargebacks, fraud warnings | `auditPlutoStripe` (a second Stripe webhook; `stripeWebhook` is untouched) | Stripe payment, Payment failed, Checkout abandoned, Refund, Chargeback, Fraud warning |

### Alerts

| Alert | Level |
| --- | --- |
| A new purchase | low |
| The paid flag set by a signed-in user or by nobody signed in (should be impossible: only `stripeWebhook` sets it) | high |
| Paid access removed | medium |
| A signed-in user wrote someone else's account, or anybody wrote with no sign-in | high |
| Fields under `users/{uid}` other than progress, review and paid | medium |
| `users/{uid}` deleted by anything but server code | high |
| 5 failed sign-ins for one email in 15 minutes; 5 and 20 from one IP | medium; medium then high |
| One IP turned away from the course 10 times in 15 minutes | medium |
| More than 60 reports from one IP in 10 minutes (the rest are dropped) | medium |
| Account email or custom claims changed outside the site; disabled or sign-in methods changed | high; medium |
| An account deleted | low |
| A refund | medium |
| A chargeback opened; a Stripe early fraud warning | high |
| A chargeback closed | low if won, medium otherwise |
| 5 requests to `auditPlutoStripe` without a valid Stripe signature from one IP in 10 minutes | high |
| On the E&C side: 5 requests to `auditIngest` with a wrong key from one IP in 10 minutes | high |

### Limits

- **plutoscan.com is on GitHub Pages, which keeps no visitor logs.** Visits and failed sign-ins are only seen when the page's own code reports them. Bots and scripts that never run the page, or call Firebase directly, are not seen by the site reports. Turning on Identity Platform's logging (step 5) keeps Google's own record of sign-in calls.
- **Payments are seen twice**: through the paid flag, which `stripeWebhook` sets, and through Stripe's own events at `auditPlutoStripe`. Card numbers are never stored, only the card brand, its country and Stripe's decline reason. A refund does not remove paid access by itself; the alert says to check the account.
- **Stripe has separate test and live webhooks.** The site uses a test key today, so set the webhook up in test mode now and again in live mode at launch. Test-mode entries are marked "Stripe test mode".
- If the E&C log can't be reached, entries wait in `security_log/unsent` and `auditPlutoCensus` sends them again every 30 minutes.
- Entries in the plutoscan copy are kept 90 days (`auditPlutoPrune`, daily at 3:45 a.m. Central). The E&C copy follows the E&C rules (90 days, alerts a year).

## Setting it up

Run these in Google Cloud Shell (https://shell.cloud.google.com), signed in as an owner of both `plutoscan` and `eandccourier-36fcc`.

1. **Identity Platform on plutoscan.** The sign-up, sign-in and email functions need it, the same as E&C. In the Firebase console for plutoscan, open Authentication, then Settings, and upgrade to Firebase Authentication with Identity Platform if it offers that. Its prices are at https://cloud.google.com/identity-platform/pricing (there is a free tier).
2. **One shared key, stored in both projects.** It never needs to be typed anywhere else. The `tr -d '\n'` matters: without it the file ends in a line break, the stored key is 65 characters, and every entry is refused as "Wrong key sent to auditIngest" (the sender's HTTP header drops the line break, the check in `auditIngest` doesn't).
   ```
   cd ~ && rm -rf usage && git clone https://github.com/ogpoopdogg/usage.git && cd usage
   openssl rand -hex 32 | tr -d '\n' > ~/ps-key
   npx firebase-tools functions:secrets:set PLUTOSCAN_AUDIT_KEY --project eandccourier-36fcc --data-file ~/ps-key
   npx firebase-tools functions:secrets:set PLUTOSCAN_AUDIT_KEY --project plutoscan --data-file ~/ps-key
   rm ~/ps-key
   ```
3. **The E&C side: just the two functions that changed.**
   ```
   cd ~/usage/functions && npm ci && cd ..
   npx firebase-tools deploy --only functions:audit:auditIngest,functions:audit:auditPrune --project eandccourier-36fcc
   ```
4. **The PlutoScan side.**
   ```
   cd ~/usage/plutoscan-audit/functions && npm ci && cd ..
   npx firebase-tools deploy --only functions:audit --project plutoscan
   npx firebase-tools functions:list --project plutoscan
   ```
   The list should show your three functions plus nine starting with `auditPluto`. If the deploy asks to delete any function, answer **No**.
5. **Stripe webhook** (for `auditPlutoStripe`). In the Stripe dashboard, open Developers, then Webhooks, and add an endpoint:
   - URL: `https://us-central1-plutoscan.cloudfunctions.net/auditPlutoStripe`
   - Events: `checkout.session.completed`, `checkout.session.expired`, `checkout.session.async_payment_failed`, `payment_intent.payment_failed`, `charge.refunded`, `charge.dispute.created`, `charge.dispute.closed`, `radar.early_fraud_warning.created`

   Copy its signing secret (starts with `whsec_`), then in Cloud Shell:
   ```
   cd ~/usage && git pull
   npx firebase-tools functions:secrets:set STRIPE_AUDIT_WEBHOOK_SECRET --project plutoscan
   cd plutoscan-audit/functions && npm ci && cd ..
   npx firebase-tools deploy --only functions:audit --project plutoscan
   ```
   (`secrets:set` asks for the value; paste the `whsec_` secret.) Then use Stripe's "Send test event" on the endpoint; a row should appear in the Security tab.
6. **Identity Platform logging** (optional, recommended): in the Google Cloud console for plutoscan, Identity Platform, Settings, turn on user activity logging.
7. **Check it.** Sign up on plutoscan.com with a test email, then open the Security tab of the usage page: a Sign-up and a Signed in row with app `plutoscan` should be there within a few seconds.

## Payment setup watch (added 2026-11-14)

So nobody can change how PlutoScan takes payments without you knowing. Every change shows in the Security tab under **Database changes** (areas starting "PlutoScan: Stripe" or "PlutoScan: Google Cloud") with the time, what changed (before and after) and who or where it came from. Alerts go through the usual phone notifications; each kind can be switched off in the Alerts settings.

| What | How it's seen | Who / where it shows | Alert |
| --- | --- | --- | --- |
| Products and prices made, changed, archived or deleted | Stripe events `product.*`, `price.*` at `auditPlutoStripe` | Stripe API request id (`req_…`), or "Stripe itself" | medium; archived or deleted high |
| Payout bank account or card added, changed or removed | Stripe events `account.external_account.*` | request id | high |
| Account settings changed | Stripe event `account.updated` | request id | medium; high for payouts, email, bank or settings |
| Payouts made, paid, failed, canceled; a payout to a different bank account than the last one | Stripe events `payout.*` | request id | failed or canceled medium; new bank account high |
| Which Stripe account checkout's key belongs to, the key's first 8 characters, the key version checkout was deployed with | `auditPlutoStripeCheck`, hourly, reads `createCheckoutSession`'s settings and the key | "Hourly Stripe check" | account or key kind changed high; new version medium |
| The price checkout sells (`STRIPE_PRICE_ID`) missing, archived or not set | hourly check | "Hourly Stripe check" | high (once, until it changes) |
| Webhook endpoints added, changed (URL, events, on/off) or removed | hourly check (up to an hour late) | "Hourly Stripe check" | high |
| New versions of `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` (or disabled, destroyed, access changed); other secrets | `auditPlutoCloudLog` from the Admin Activity audit log | Google account, IP address, tool | Stripe secrets high; others medium |
| Deploys and deletes of `createCheckoutSession`, `stripeWebhook`, `getModuleContent` | same | Google account, IP address, tool | medium; delete high |
| Deploys of other functions (the audit ones) | same | same | logged only |
| Who has access to the plutoscan project; the log sink itself | same | same | high |

### What Stripe and Google can't tell

- **Webhook endpoint changes have no Stripe event** (none in Stripe's event type list, https://docs.stripe.com/api/events/types), so the hourly check compares the list instead. It can be up to an hour late and can't say who.
- **Team member changes and API keys being made or rolled have no Stripe event, and there's no API to list team members.** They can't be watched. Check Stripe → Settings → Team and security now and then. A rolled key that ends up in `STRIPE_SECRET_KEY` is still caught by the secret version alert and the hourly check.
- **Stripe events don't say which Dashboard user or IP made a change.** They carry only the API request id; Stripe's field description says request logs are "available in the dashboard, but currently not in the API" (https://docs.stripe.com/api/events/object). Look the `req_…` up in Stripe → Developers → Logs.
- **Bank account events for your own account:** Stripe's event list doesn't say whether `account.external_account.*` fire for your own account or only for Connect accounts. Not confirmed until one happens; the payout-destination check backs it up.
- **Reading a secret isn't watched.** That's in Data Access audit logs, which are off by default (https://docs.cloud.google.com/secret-manager/docs/audit-logging). Adding versions, creating, disabling and destroying are Admin Activity logs, which are always on and free (https://docs.cloud.google.com/logging/docs/audit, https://cloud.google.com/logging/pricing).
- Secrets are never stored or shown: keys at most their first 8 characters (`sk_live_`), and fields named like secrets, account or routing numbers are dropped. The request body of a Google audit entry is never read.

### Setting it up

1. Merge the pull request.
2. **Stripe dashboard**, in the same Stripe account (and live or test mode) that checkout uses: Developers → Webhooks → add an endpoint (Stripe may call it a "destination"), events from **Your account**, URL `https://us-central1-plutoscan.cloudfunctions.net/auditPlutoStripe`, events: all Product, all Price, all Payout, `account.updated`, `account.external_account.created`, `account.external_account.updated`, `account.external_account.deleted`, plus the 8 from step 5 above. Copy the signing secret (`whsec_…`). If `auditPlutoStripe` already exists from step 5, edit it and add the new events instead.
3. **Cloud Shell**, signed in as an owner of both projects:
   ```
   cd ~ && rm -rf usage && git clone -q https://github.com/ogpoopdogg/usage.git && cd usage && bash scripts/setup-plutoscan-payment-watch.sh
   ```
   It grants the audit functions read access to `createCheckoutSession`'s settings (Cloud Functions Viewer) and to `STRIPE_SECRET_KEY`, makes the topic `plutoscan-cloud-log` and a log sink feeding it, asks for the signing secret (typing is hidden), deploys the `audit` codebase to plutoscan and `auditIngest` + `auditAlertPush` to E&C, and runs the first check.

Costs: log sinks and Admin Activity logs are free; Pub/Sub's first 10 GiB a month is free (https://cloud.google.com/pubsub/pricing) and this sends a few MB at most; about 750 more function runs a month.

## Tests

```
cd functions && npm test
```

The tests cover `setup.js` (payment setup watch: Stripe events, the hourly check's comparisons, Google audit log entries, and that no secret is kept) and `lib.js`: site reports, purchases and the paid flag, account data alerts, the census, Stripe signature checks and Stripe events. Both projects were also run end to end in the Firebase emulators: sign-up, wrong password, progress and review saves, a user trying to set paid and to write another account (refused by the rules, nothing logged), the paid flag set by server code, each kind of site report, the failed sign-in alert, a wrong key at `auditIngest`, and entries waiting in `unsent` while the E&C side was down. `auditPlutoStripe` was run the same way with signed events, a repeated event (logged once), an ignored event type and five forged ones (refused, then an alert). The emulator sends every non-create blocking event to one function and doesn't say who wrote a database change, so those two parts can only be confirmed after deploying.
