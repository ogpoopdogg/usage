#!/usr/bin/env bash
# Fix 12 from the 2026-11-04 security review: each group of Cloud Functions runs as its own Google
# account with only the rights it needs, instead of the default compute account that has Editor on
# the whole project (README, "Robot keys"). Run in Cloud Shell from this repo's top folder after the
# usage, timeclock and dispatch pull requests are merged:
#     git pull && bash scripts/setup-robot-keys.sh
# Only ADDS accounts and rights, then redeploys and tests. It does not take Editor away from the
# default accounts: that is a separate step once everything has run on the new accounts for a few
# days. Asks before each deploy, so you can stop if a test fails. Safe to run again.
set -u
P=eandccourier-36fcc
PN=$(gcloud projects describe $P --format='value(projectNumber)')
MAIN_BUCKET=eandccourier-36fcc-default-rtdb-backups
VAULT_BUCKET=eandccourier-36fcc-backup-vault
AUDIT=ec-audit@$P.iam.gserviceaccount.com
APPS=ec-apps@$P.iam.gserviceaccount.com
GPS=ec-gps@$P.iam.gserviceaccount.com
OUT=~/robot-keys-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$OUT"
step() { echo; echo "=== $*"; }
ask() { local a; read -r -p "$1 Type yes to go ahead: " a; [ "$a" = yes ]; }
grant() { gcloud projects add-iam-policy-binding $P --member="serviceAccount:$1" --role="$2" --condition=None --format='value(etag)' >/dev/null && echo "  $2"; }
FB() { npx -y firebase-tools "$@"; }

step "1. The three accounts"
gcloud iam service-accounts create ec-audit --project $P --display-name="EC security watchers (usage)" 2>&1 | tail -1
gcloud iam service-accounts create ec-apps --project $P --display-name="EC time clock and Dispatch functions" 2>&1 | tail -1
gcloud iam service-accounts create ec-gps --project $P --display-name="EC van GPS functions (pollNow, pajApi)" 2>&1 | tail -1
sleep 10   # a new account takes a few seconds before rights can be given to it

step "2. What the security watchers may do ($AUDIT)"
for r in roles/firebasedatabase.admin roles/firebaseauth.viewer roles/firebasecloudmessaging.admin roles/monitoring.viewer roles/logging.logWriter roles/eventarc.eventReceiver roles/run.invoker; do grant $AUDIT $r; done
gcloud storage buckets add-iam-policy-binding gs://$MAIN_BUCKET --member="serviceAccount:$AUDIT" --role=roles/storage.objectCreator --format='value(etag)' >/dev/null && echo "  main backup bucket: add files"
gcloud storage buckets add-iam-policy-binding gs://$MAIN_BUCKET --member="serviceAccount:$AUDIT" --role=roles/storage.objectViewer --format='value(etag)' >/dev/null && echo "  main backup bucket: read files (to copy them to the vault)"
gcloud storage buckets add-iam-policy-binding gs://$VAULT_BUCKET --member="serviceAccount:$AUDIT" --role=roles/storage.objectCreator --format='value(etag)' >/dev/null && echo "  vault bucket: add files only"
gcloud pubsub topics add-iam-policy-binding security-canary --project $P --member="serviceAccount:$AUDIT" --role=roles/pubsub.editor --format='value(etag)' >/dev/null && echo "  security-canary topic (the morning test changes its label)"
for s in GITHUB_WEBHOOK_SECRET PLUTOSCAN_AUDIT_KEY; do
  gcloud secrets add-iam-policy-binding $s --project $P --member="serviceAccount:$AUDIT" --role=roles/secretmanager.secretAccessor --format='value(etag)' >/dev/null && echo "  secret $s"
done

step "3. What the time clock and Dispatch functions may do ($APPS)"
for r in roles/firebasedatabase.admin roles/firebasecloudmessaging.admin roles/logging.logWriter roles/eventarc.eventReceiver roles/run.invoker; do grant $APPS $r; done

step "4. What the van GPS functions may do ($GPS)"
for r in roles/firebasedatabase.admin roles/logging.logWriter; do grant $GPS $r; done
for s in PAJ_EMAIL PAJ_PASSWORD FLEETHUNT_KEY; do
  gcloud secrets add-iam-policy-binding $s --project $P --member="serviceAccount:$GPS" --role=roles/secretmanager.secretAccessor --format='value(etag)' >/dev/null && echo "  secret $s"
done

step "5. Let Pub/Sub sign its calls to the functions (Google's default for older projects)"
grant service-$PN@gcp-sa-pubsub.iam.gserviceaccount.com roles/iam.serviceAccountTokenCreator

# A test after each deploy: run the scheduled watchers and the morning test, then look at what ran
# and at any "permission denied" in the last few minutes.
check_audit() {
  for j in auditCanary auditRulesCheck auditUsageCheck auditBackup; do
    gcloud scheduler jobs run firebase-schedule-$j-us-central1 --project $P --location us-central1 >/dev/null && echo "  started $j"
  done
  echo "  waiting 3 minutes"; sleep 180
  FB database:get /security_log/last --project $P > "$OUT/last.json" 2>/dev/null
  python3 - "$OUT/last.json" <<'EOF'
import json, sys, time
last = json.load(open(sys.argv[1])) or {}
for k in ['auditCanary', 'canaryWatch', 'cloudFeed', 'auditRulesCheck', 'auditUsageCheck', 'auditBackup', 'auditBackupVault']:
    v = last.get(k)
    ok = isinstance(v, (int, float)) and time.time() * 1000 - v < 6 * 60 * 1000
    print('  ' + ('OK      ' if ok else 'NOT YET ') + k)
EOF
}
denied() {
  echo "  'permission denied' errors from functions in the last 10 minutes (none is good):"
  gcloud logging read 'resource.type="cloud_run_revision" AND severity>=ERROR AND textPayload:("PERMISSION_DENIED" OR "permission" OR "403")' --project $P --freshness=10m --limit=20 --format='value(timestamp,resource.labels.service_name,textPayload)' | cut -c1-300
}

step "6. Security watchers: deploy them on their own account, then test"
if ask "Deploy the usage functions (about 15 minutes)?"; then
  cd functions && npm ci --silent && cd ..
  NAMES=$(cd functions && GCLOUD_PROJECT=$P node -e "console.log(Object.keys(require('./index')).join(' '))")
  set -- $NAMES
  while [ $# -gt 0 ]; do
    B=""; for i in 1 2 3 4 5 6 7 8 9 10; do [ $# -gt 0 ] && { B="$B $1"; shift; }; done
    ONLY=$(for f in $B; do printf 'functions:audit:%s,' "$f"; done); ONLY=${ONLY%,}
    echo "---$B"
    FB deploy --only "$ONLY" --project $P --force 2>&1 | grep -E 'Successful|Error|error|Deploy complete' | tail -12
    sleep 20
  done
  check_audit
  denied
fi

step "7. Time clock and Dispatch: deploy on their own account"
if ask "Deploy the time clock and Dispatch functions?"; then
  for r in timeclock dispatch; do [ -d ~/$r/.git ] || git clone -q https://github.com/ogpoopdogg/$r ~/$r; git -C ~/$r pull -q; (cd ~/$r/functions && npm ci --silent); done
  (cd ~/timeclock && FB deploy --only functions:timeclock --project $P --force 2>&1 | grep -E 'Successful|Error|error|Deploy complete' | tail -5)
  # Names one by one, so this never touches pollNow or pajApi
  D=$(cd ~/dispatch/functions && node -e "console.log(Object.keys(require('./index')).map(n=>'functions:default:'+n).join(','))")
  (cd ~/dispatch && FB deploy --only "$D" --project $P --force 2>&1 | grep -E 'Successful|Error|error|Deploy complete' | tail -8)
  for j in remindQueue fillHistoryKeys; do gcloud scheduler jobs run firebase-schedule-$j-us-central1 --project $P --location us-central1 >/dev/null && echo "  started $j"; done
  sleep 60; denied
  echo "  Now press the test notification button in Dispatch, and check you get it."
fi

step "8. Van GPS (pollNow, pajApi): switch their account"
if ask "Switch pollNow and pajApi to their own account?"; then
  for s in pollnow pajapi; do
    gcloud run services update $s --project $P --region us-central1 --service-account=$GPS --quiet 2>&1 | tail -2
  done
  echo "  Open RouteWatcher: vans should keep moving and Show Track should work."
  sleep 60; denied
fi

echo
echo "Done. Send Claude this printout. The default accounts still have Editor; that comes off later,"
echo "after a few days with everything running on the new accounts. To undo a GPS switch:"
echo "  gcloud run services update pollnow --region us-central1 --service-account=$PN-compute@developer.gserviceaccount.com"
