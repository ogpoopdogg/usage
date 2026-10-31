#!/usr/bin/env bash
# One-time setup for the extra watches (README, "Extra watches"). Run in Cloud Shell from the
# repo's top folder after the pull request is merged:  bash scripts/setup-extra-watches.sh
# Safe to run again: steps that already happened say so and carry on.
set -u
P=eandccourier-36fcc
BILLING=01C8D9-CFEC46-1D9AC4
BUDGET_CAD=${BUDGET_CAD:-25}
PN=$(gcloud projects describe $P --format='value(projectNumber)')
SA="${PN}-compute@developer.gserviceaccount.com"
step() { echo; echo "=== $*"; }

step "1. Let the functions read Cloud Monitoring (download check)"
gcloud projects add-iam-policy-binding $P --member="serviceAccount:$SA" --role=roles/monitoring.viewer --condition=None --format='value(etag)' >/dev/null && echo "ok"

step "2. Pub/Sub topics"
gcloud services enable pubsub.googleapis.com billingbudgets.googleapis.com --project $P
for t in security-cloud-log security-budget; do
  gcloud pubsub topics create $t --project $P 2>&1 | tail -1
done

step "3. Log sink for Google Cloud changes"
FILTER='logName="projects/'$P'/logs/cloudaudit.googleapis.com%2Factivity" AND (protoPayload.methodName:"SetIamPolicy" OR protoPayload.methodName:"ServiceAccount" OR protoPayload.methodName:"apikeys" OR protoPayload.methodName:"Function" OR protoPayload.methodName:"storage.buckets" OR protoPayload.methodName:"storage.setIamPermissions" OR protoPayload.methodName:"Ruleset" OR protoPayload.methodName:"Release" OR protoPayload.methodName:"CloudScheduler")'
gcloud logging sinks create security-cloud-log pubsub.googleapis.com/projects/$P/topics/security-cloud-log --project $P --log-filter="$FILTER" 2>&1 | tail -2 \
  || true
gcloud logging sinks update security-cloud-log pubsub.googleapis.com/projects/$P/topics/security-cloud-log --project $P --log-filter="$FILTER" >/dev/null 2>&1
WI=$(gcloud logging sinks describe security-cloud-log --project $P --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding security-cloud-log --project $P --member="$WI" --role=roles/pubsub.publisher --format='value(etag)' >/dev/null && echo "sink can publish ($WI)"

step "4. Spending budget (CA\$$BUDGET_CAD a month, E&C project only)"
if gcloud billing budgets list --billing-account=$BILLING --format='value(displayName)' 2>/dev/null | grep -qx 'E&C security budget'; then
  echo "already there"
else
  gcloud billing budgets create --billing-account=$BILLING --display-name='E&C security budget' \
    --budget-amount=${BUDGET_CAD}CAD --filter-projects=projects/$P \
    --threshold-rule=percent=0.25 --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 \
    --threshold-rule=percent=1.0 --threshold-rule=percent=2.0 \
    --notifications-rule-pubsub-topic=projects/$P/topics/security-budget | tail -3
fi

step "5. GitHub webhook secret"
if gcloud secrets describe GITHUB_WEBHOOK_SECRET --project $P >/dev/null 2>&1; then
  echo "already there (your copy: ~/github-webhook-secret.txt, if this Cloud Shell made it)"
else
  openssl rand -hex 32 | tr -d '\n' > ~/github-webhook-secret.txt
  npx -y firebase-tools functions:secrets:set GITHUB_WEBHOOK_SECRET --data-file ~/github-webhook-secret.txt --project $P --force
  echo "Saved. Paste this into each GitHub webhook's Secret box:"
fi
[ -f ~/github-webhook-secret.txt ] && cat ~/github-webhook-secret.txt && echo

step "6. Deploy the audit functions in batches"
cd functions && npm ci --silent && cd ..
BATCHES=(
  "auditRulesCheck auditUsageCheck auditCloudLog auditBudget auditGitHub auditHeartbeat auditDispatchContacts auditDispatchSettings"
  "auditBeforeSignIn auditUserCreated auditUserDeleted auditUserCensus auditPrune auditBackup auditAlertPush auditTestPush"
  "auditAddressLookup auditStaff auditRoles auditJobs auditRequests auditCompanies auditJoinCodes auditUsers"
  "auditPushTokens auditAllowedUsers auditMasterConfig auditNicknames auditSessions auditRoutePlanner auditTcEmployees auditTcSettings"
  "auditTcShifts auditTcRequests auditTcVanReports auditTcVans auditTcOilPlan auditTcVehicleClaims auditGarage"
  "auditSignInReport auditBeforeEmail auditBeforeSms auditIngest"
)
for b in "${BATCHES[@]}"; do
  ONLY=$(for f in $b; do printf 'functions:audit:%s,' "$f"; done); ONLY=${ONLY%,}
  echo "--- $b"
  npx -y firebase-tools deploy --only "$ONLY" --project $P --force 2>&1 | grep -E 'Successful|Error|error|✔  functions\[|Deploy complete' | tail -12
  sleep 30
done

step "7. First run of the hourly checks"
for f in auditRulesCheck auditUsageCheck; do
  gcloud scheduler jobs run firebase-schedule-$f-us-central1 --project $P --location=us-central1 && echo "$f started"
done
echo
echo "Done. Next: add the GitHub webhook to each repository (README, Extra watches, step 7)."
