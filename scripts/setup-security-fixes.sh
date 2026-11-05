#!/usr/bin/env bash
# The fixes Justin picked from the 2026-11-04 security review (README, "Security fixes, 2026-11-04").
# Run in Cloud Shell from this repo's top folder, after the usage and timeclock pull requests are
# merged:   git pull && bash scripts/setup-security-fixes.sh
# Safe to run again: steps that already happened say so and carry on. Two steps ask before doing
# anything (the database rules, and deleting fleetHuntHistory); key files are only disabled, which
# can be undone. Nothing here deletes time clock or Request Pickup data.
set -u
P=eandccourier-36fcc
BILLING=01C8D9-CFEC46-1D9AC4
VAULT_PROJECT=${VAULT_PROJECT:-eandccourier-36fcc-vault}
VAULT_BUCKET=eandccourier-36fcc-backup-vault          # same as functions/backup.js VAULT_BUCKET
MAIN_BUCKET=eandccourier-36fcc-default-rtdb-backups   # same as functions/backup.js BUCKET
PN=$(gcloud projects describe $P --format='value(projectNumber)')
SA="${PN}-compute@developer.gserviceaccount.com"
OUT=~/security-fixes-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"
step() { echo; echo "=== $*"; }
ask() { local a; read -r -p "$1 Type yes to go ahead: " a; [ "$a" = yes ]; }
FB() { npx -y firebase-tools "$@"; }

step "1. Pub/Sub topics for the morning test and the sign-in log"
for t in security-canary security-signin-log; do
  gcloud pubsub topics create $t --project $P 2>&1 | tail -1
done

step "2. Google Cloud alert feed: also the feed itself, sign-in settings, Cloud Run and the database"
FILTER='logName="projects/'$P'/logs/cloudaudit.googleapis.com%2Factivity" AND (protoPayload.methodName:"SetIamPolicy" OR protoPayload.methodName:"ServiceAccount" OR protoPayload.methodName:"apikeys" OR protoPayload.methodName:"Function" OR protoPayload.methodName:"storage.buckets" OR protoPayload.methodName:"storage.setIamPermissions" OR protoPayload.methodName:"Ruleset" OR protoPayload.methodName:"Release" OR protoPayload.methodName:"CloudScheduler" OR protoPayload.methodName:"ConfigServiceV2" OR protoPayload.methodName:"google.pubsub" OR protoPayload.methodName:"identitytoolkit" OR protoPayload.methodName:"google.cloud.run" OR protoPayload.methodName:"DatabaseInstance")'
gcloud logging sinks update security-cloud-log pubsub.googleapis.com/projects/$P/topics/security-cloud-log --project $P --log-filter="$FILTER" >/dev/null && echo "filter updated"

step "3. Sign-in log feed (failed passwords sent straight to Firebase)"
SFILTER='logName="projects/'$P'/logs/identitytoolkit.googleapis.com%2Frequests" AND (jsonPayload.methodName:"SignInWithPassword" OR protoPayload.methodName:"SignInWithPassword")'
gcloud logging sinks create security-signin-log pubsub.googleapis.com/projects/$P/topics/security-signin-log --project $P --log-filter="$SFILTER" 2>&1 | tail -1
gcloud logging sinks update security-signin-log pubsub.googleapis.com/projects/$P/topics/security-signin-log --project $P --log-filter="$SFILTER" >/dev/null 2>&1
WI=$(gcloud logging sinks describe security-signin-log --project $P --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding security-signin-log --project $P --member="$WI" --role=roles/pubsub.publisher --format='value(etag)' >/dev/null && echo "sink can publish ($WI)"
echo "Entries seen in the last day (0 is fine if nobody signed in with a password):"
gcloud logging read "$SFILTER" --project $P --freshness=1d --limit=50 --format='value(timestamp)' | wc -l

step "4. Main backup bucket: deleted files can be brought back for 30 days (was 7)"
gcloud storage buckets update gs://$MAIN_BUCKET --soft-delete-duration=30d --format='value(name)' && echo "ok"

step "5. Off-site copy in a second project ($VAULT_PROJECT)"
if ! gcloud projects describe $VAULT_PROJECT >/dev/null 2>&1; then
  gcloud projects create $VAULT_PROJECT --name="EC backup vault"   # "&" is not allowed in a project name || { echo "Couldn't make the project. If the name is taken, run again with VAULT_PROJECT=another-name, and tell Claude the name."; }
fi
gcloud billing projects link $VAULT_PROJECT --billing-account=$BILLING --format='value(billingEnabled)'
gcloud services enable storage.googleapis.com --project $VAULT_PROJECT
LOC=$(gcloud storage buckets describe gs://$MAIN_BUCKET --format='value(location)')
if ! gcloud storage buckets describe gs://$VAULT_BUCKET >/dev/null 2>&1; then
  gcloud storage buckets create gs://$VAULT_BUCKET --project $VAULT_PROJECT --location="$LOC" \
    --uniform-bucket-level-access --public-access-prevention
fi
# daily/ copies go after 90 days; monthly/ (the 1st of each month) are kept for good
cat > "$OUT/vault-lifecycle.json" <<'EOF'
{"rule": [{"action": {"type": "Delete"}, "condition": {"age": 90, "matchesPrefix": ["daily/"]}}]}
EOF
# Nothing can be deleted or replaced for 30 days (not locked, so it can still be changed later),
# and anything deleted after that can be brought back for 90 days.
gcloud storage buckets update gs://$VAULT_BUCKET --retention-period=30d --soft-delete-duration=90d \
  --lifecycle-file="$OUT/vault-lifecycle.json" --format='value(name)'
# The functions may only add files there: no reading, replacing or deleting
gcloud storage buckets add-iam-policy-binding gs://$VAULT_BUCKET --member="serviceAccount:$SA" --role=roles/storage.objectCreator --format='value(etag)' >/dev/null && echo "functions can add files"
gcloud storage buckets describe gs://$VAULT_BUCKET --format='yaml(name,location,retention_policy,soft_delete_policy,lifecycle_config)'

step "6. Deploy the audit functions in batches"
cd functions && npm ci --silent && cd ..
BATCHES=(
  "auditRulesCheck auditUsageCheck auditCloudLog auditBudget auditGitHub auditHeartbeat auditCanary auditSignInLog auditNotifyChange"
  "auditBeforeSignIn auditBeforeEmail auditBeforeSms auditUserCreated auditUserDeleted auditUserCensus auditPrune auditBackup auditAlertPush auditTestPush"
  "auditAddressLookup auditStaff auditRoles auditJobs auditRequests auditCompanies auditJoinCodes auditUsers auditPushTokens auditAllowedUsers"
  "auditMasterConfig auditNicknames auditSessions auditRoutePlanner auditTcEmployees auditTcSettings auditTcShifts auditTcRequests auditTcVanReports auditTcVans"
  "auditTcOilPlan auditTcVehicleClaims auditGarage auditDispatchContacts auditDispatchSettings auditDevNotes auditLoginRefusals auditCanaryWatch"
  "auditUserOrders auditAddressLookupDelivery auditDeliveryLookup auditOldDrivers auditOldDriverLocations auditOldCommandTokens auditOldGeofences auditOldZones auditOldSchedules"
  "auditSignInReport auditIngest"
)
for b in "${BATCHES[@]}"; do
  ONLY=$(for f in $b; do printf 'functions:audit:%s,' "$f"; done); ONLY=${ONLY%,}
  echo "--- $b"
  FB deploy --only "$ONLY" --project $P --force 2>&1 | grep -E 'Successful|Error|error|✔  functions\[|Deploy complete' | tail -14
  sleep 30
done

step "7. The morning test, once now"
gcloud scheduler jobs run firebase-schedule-auditCanary-us-central1 --project $P --location=us-central1 && echo "started; waiting 2 minutes"
sleep 120
FB database:get /security_log/last --project $P > "$OUT/last.json" 2>/dev/null
python3 - "$OUT/last.json" <<'EOF'
import json, sys, time
last = json.load(open(sys.argv[1])) or {}
for k, what in [('auditCanary', 'the morning test ran'), ('canaryWatch', 'the database watchers saw it'), ('cloudFeed', 'the Google Cloud feed passed it on')]:
    v = last.get(k)
    v = v.get('at') if isinstance(v, dict) else v
    ok = isinstance(v, (int, float)) and time.time() * 1000 - v < 15 * 60 * 1000
    print(('OK   ' if ok else 'NOT YET ') + what + (' (' + k + ')'))
print('A "NOT YET" on the Google Cloud feed can just be a slow log; it is checked again at 8 AM.')
EOF

step "8. Time clock: only the admin panel can make new @ec.com sign-ins"
TC=~/timeclock
[ -d $TC/.git ] || git clone -q https://github.com/ogpoopdogg/timeclock $TC
git -C $TC pull -q
if curl -fsSL "https://app.eandccourier.ca/timeclock/admin.html?nocache=$(date +%s)" | grep -q signup_ok; then
  (cd $TC/functions && npm ci --silent)
  (cd $TC && npx -y firebase-tools deploy --only functions:timeclock:timeclockBeforeUserCreated --project $P --force 2>&1 | grep -E 'Successful|Error|error|Deploy complete' | tail -5)
else
  echo "SKIPPED: the live admin page doesn't have the change yet (merge the timeclock pull request, wait a few minutes for the site, then run this again)."
  echo "Deploying the server check before the page would stop the admin page from making new sign-ins."
fi

step "9. Database rules: celeste removed, unused areas locked, users capped, developer notes moved"
FB database:get /security_log/rules_watch --project $P > "$OUT/rules-watch.json"
python3 - "$OUT/rules-watch.json" "$OUT/rules-before.json" <<'EOF'
import json, sys, time
w = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(w['text'])
print('Live rules as of the last 10-minute check: %d characters, last changed %s' % (len(w['text']), time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(w['at'] / 1000))))
EOF
python3 scripts/rules-update-2026-11-04.py --in "$OUT/rules-before.json" --out "$OUT/rules-after.json" || exit 1
echo "Your old rules are saved in $OUT/rules-before.json (the daily backup also keeps a copy)."
if ask "Deploy the new rules?"; then
  printf '{ "database": { "rules": "rules-after.json" } }\n' > "$OUT/firebase.json"
  (cd "$OUT" && npx -y firebase-tools deploy --only database --project $P 2>&1 | grep -E 'Error|error|released|Deploy complete' | tail -5)
  echo "Expect one 'Database rules changed' alert within 10 minutes: that's this change."
  echo "To undo: Firebase console, Realtime Database, Rules, paste $OUT/rules-before.json, Publish."
else
  echo "Rules not changed."
fi

step "10. The three helper programs nobody has the code for"
mkdir -p ~/fn-sources
for f in pajApi pollNow fleetHuntHistory; do
  gcloud functions describe $f --region=us-central1 --project $P --format=json > "$OUT/$f.json" 2>/dev/null || { echo "$f: not found"; continue; }
  SRC=$(python3 - "$OUT/$f.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
s = ((d.get('buildConfig') or {}).get('source') or {}).get('storageSource') or {}
print('gs://%s/%s' % (s['bucket'], s['object']) if s.get('bucket') else d.get('sourceArchiveUrl', ''))
EOF
)
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[2]+': runs as', (d.get('serviceConfig') or {}).get('serviceAccountEmail') or d.get('serviceAccountEmail'))" "$OUT/$f.json" $f
  if [ -n "$SRC" ] && gcloud storage cp "$SRC" ~/fn-sources/$f.zip >/dev/null 2>&1; then echo "$f: code saved to ~/fn-sources/$f.zip"; else echo "$f: Google no longer keeps its code ($SRC)"; fi
done
FB database:get /developer/dispatch_dashboard/drivers --project $P > "$OUT/drivers.json" 2>/dev/null
FH=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])) or {}; print(sum(1 for v in d.values() if isinstance(v, dict) and v.get('provider') == 'fleethunt'))" "$OUT/drivers.json" 2>/dev/null || echo '?')
echo "RouteWatcher drivers still set to FleetHunt: $FH (only those use fleetHuntHistory)"
if [ -f ~/fn-sources/fleetHuntHistory.zip ] || [ "$FH" = 0 ]; then
  if ask "Delete fleetHuntHistory?"; then gcloud functions delete fleetHuntHistory --region=us-central1 --project $P --quiet; fi
else
  echo "fleetHuntHistory kept: its code couldn't be saved and FleetHunt drivers may still use it."
fi
echo "Download ~/fn-sources (Cloud Shell's three-dot menu, Download) and send the zip files to Claude to review."

step "11. The two spare master keys (key files for the Firebase admin robot)"
KSA=firebase-adminsdk-fbsvc@$P.iam.gserviceaccount.com
gcloud services enable policyanalyzer.googleapis.com --project $P
gcloud iam service-accounts keys list --iam-account=$KSA --managed-by=user --project $P --format='table(name.basename():label=KEY,validAfterTime:label=MADE,disabled)'
echo "When each key was last used (no line = not used in the last 2 months or so):"
gcloud policy-intelligence query-activity --activity-type=serviceAccountKeyLastAuthentication --project=$P \
  --format='table(activity.serviceAccountKey.fullResourceName.basename():label=KEY,activity.lastAuthenticatedTime:label=LAST_USED)' 2>&1 | tail -n +1
if ask "Disable both key files now? (Undo any time with: gcloud iam service-accounts keys enable KEY --iam-account=$KSA)"; then
  for k in $(gcloud iam service-accounts keys list --iam-account=$KSA --managed-by=user --project $P --format='value(name.basename())'); do
    gcloud iam service-accounts keys disable $k --iam-account=$KSA --project $P --quiet && echo "disabled $k"
  done
  echo "If nothing breaks in a week, tell Claude and they get deleted for good."
fi
echo "Stopping new key files (needs the project to be in a Google organization; it says so if not):"
gcloud resource-manager org-policies enable-enforce iam.disableServiceAccountKeyCreation --project=$P 2>&1 | tail -2

echo
echo "Done. Everything this printed is easier to read in $OUT. Next:"
echo " - Reset a staff password: bash scripts/set-staff-password.sh name@ec.com"
echo " - Sign in once with a wrong password on purpose, then check security_log/signin_log_samples (tells Claude the log's fields)."
