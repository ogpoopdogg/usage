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
2. **One shared key, stored in both projects.** It never needs to be typed anywhere else.
   ```
   cd ~ && rm -rf usage && git clone https://github.com/ogpoopdogg/usage.git && cd usage
   openssl rand -hex 32 > ~/ps-key
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

## Tests

```
cd functions && npm test
```

The tests cover `lib.js`: site reports, purchases and the paid flag, account data alerts, the census, Stripe signature checks and Stripe events. Both projects were also run end to end in the Firebase emulators: sign-up, wrong password, progress and review saves, a user trying to set paid and to write another account (refused by the rules, nothing logged), the paid flag set by server code, each kind of site report, the failed sign-in alert, a wrong key at `auditIngest`, and entries waiting in `unsent` while the E&C side was down. `auditPlutoStripe` was run the same way with signed events, a repeated event (logged once), an ignored event type and five forged ones (refused, then an alert). The emulator sends every non-create blocking event to one function and doesn't say who wrote a database change, so those two parts can only be confirmed after deploying.
