#!/usr/bin/env bash
# One-time setup for the PlutoScan payment setup watch (plutoscan-audit/README.md, "Payment setup
# watch"). Run in Cloud Shell from the repo's top folder after the pull request is merged:
#   bash scripts/setup-plutoscan-payment-watch.sh
# It asks for the Stripe signing secret (whsec_...) of the auditPlutoStripe endpoint. Nothing it
# prints shows more than the first 8 characters of any secret. Safe to run again.
set -u
P=plutoscan
EC=eandccourier-36fcc
TOPIC=plutoscan-cloud-log
PN=$(gcloud projects describe $P --format='value(projectNumber)')
SA="${PN}-compute@developer.gserviceaccount.com"
step() { echo; echo "=== $*"; }

step "1. Turn on the Google services the watch uses"
gcloud services enable pubsub.googleapis.com secretmanager.googleapis.com cloudfunctions.googleapis.com --project $P && echo "ok"

step "2. Let the audit functions read checkout's settings and its Stripe key (read only)"
gcloud projects add-iam-policy-binding $P --member="serviceAccount:$SA" --role=roles/cloudfunctions.viewer --condition=None --format='value(etag)' >/dev/null && echo "Cloud Functions Viewer: ok"
gcloud secrets add-iam-policy-binding STRIPE_SECRET_KEY --project $P --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor --condition=None --format='value(etag)' >/dev/null && echo "Read STRIPE_SECRET_KEY: ok"

step "3. Log feed for Google Cloud changes (topic $TOPIC + log sink)"
gcloud pubsub topics create $TOPIC --project $P 2>&1 | tail -1
FILTER='logName="projects/'$P'/logs/cloudaudit.googleapis.com%2Factivity" AND (protoPayload.serviceName="secretmanager.googleapis.com" OR protoPayload.serviceName="cloudfunctions.googleapis.com" OR (protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND protoPayload.methodName:"SetIamPolicy") OR protoPayload.methodName:"ConfigServiceV2" OR protoPayload.methodName:"Publisher.DeleteTopic")'
gcloud logging sinks create $TOPIC pubsub.googleapis.com/projects/$P/topics/$TOPIC --project $P --log-filter="$FILTER" 2>&1 | tail -1 || true
gcloud logging sinks update $TOPIC pubsub.googleapis.com/projects/$P/topics/$TOPIC --project $P --log-filter="$FILTER" >/dev/null 2>&1
WI=$(gcloud logging sinks describe $TOPIC --project $P --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding $TOPIC --project $P --member="$WI" --role=roles/pubsub.publisher --format='value(etag)' >/dev/null && echo "sink can publish: ok"

step "4. Stripe signing secret for auditPlutoStripe"
HAVE=$(gcloud secrets versions list STRIPE_AUDIT_WEBHOOK_SECRET --project $P --filter=state=enabled --format='value(name)' 2>/dev/null | head -1)
[ -n "$HAVE" ] && echo "A signing secret is already stored (version $HAVE). Press Enter to keep it, or paste a new one."
read -rsp "Paste the Stripe signing secret (starts with whsec_), then press Enter: " WHSEC; echo
WHSEC=$(printf '%s' "$WHSEC" | tr -d '[:space:]')
if [ -n "$WHSEC" ]; then
case "$WHSEC" in
whsec_*)
F=$(mktemp); printf '%s' "$WHSEC" > "$F"
npx -y firebase-tools functions:secrets:set STRIPE_AUDIT_WEBHOOK_SECRET --project $P --data-file "$F" && echo "Stored: ${WHSEC:0:8}... (only the start is shown)"
rm -f "$F" ;;
*) echo "That doesn't start with whsec_ - nothing stored. Run this script again and paste the signing secret."; exit 1 ;;
esac
elif [ -z "$HAVE" ]; then
echo "No signing secret given and none stored - run this script again and paste it."; exit 1
fi
unset WHSEC

step "5. Deploy the PlutoScan audit functions (your own functions are not touched)"
(cd plutoscan-audit/functions && npm ci --no-audit --no-fund >/dev/null) && (cd plutoscan-audit && npx -y firebase-tools deploy --only functions:audit --project $P) || { echo "Deploy failed: copy the red lines above and send them to Claude."; exit 1; }

step "6. Deploy the 2 E&C functions that know the new alert kinds"
(cd functions && npm ci --no-audit --no-fund >/dev/null) && npx -y firebase-tools deploy --only functions:audit:auditIngest,functions:audit:auditAlertPush --project $EC || { echo "E&C deploy failed: copy the red lines above and send them to Claude."; exit 1; }

step "7. Run the first Stripe check now"
gcloud scheduler jobs run firebase-schedule-auditPlutoStripeCheck-us-central1 --location us-central1 --project $P && echo "Started. Its first look shows in the usage app (Security, Database changes, area PlutoScan: Stripe hourly check) within a minute."

echo; echo "=== Done. Send Claude a screenshot of this screen."
