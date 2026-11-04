#!/usr/bin/env bash
# Sets a new password for an E&C sign-in, from Cloud Shell. Since 2026-11-04 Firebase no longer
# emails password resets to @ec.com addresses (whoever owns ec.com would get them), so this is how a
# staff password is reset.   Usage: bash scripts/set-staff-password.sh name@ec.com
# Uses Identity Platform's accounts.lookup and accounts.update with your own Google sign-in:
# https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/update
set -euo pipefail
P=eandccourier-36fcc
EMAIL=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
[ -n "$EMAIL" ] || { echo "Usage: bash scripts/set-staff-password.sh name@ec.com"; exit 1; }
API=https://identitytoolkit.googleapis.com/v1/projects/$P
call() { curl -fsS -X POST "$API/$1" -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "x-goog-user-project: $P" -H 'Content-Type: application/json' -d @-; }

UID_=$(printf '{"email":["%s"]}' "$EMAIL" | call accounts:lookup | python3 -c 'import json,sys; u=json.load(sys.stdin).get("users") or []; print(u[0]["localId"] if u else "")')
[ -n "$UID_" ] || { echo "No sign-in with the email $EMAIL."; exit 1; }
read -r -s -p "New password for $EMAIL (12 characters or more): " PW; echo
[ ${#PW} -ge 12 ] || { echo "Too short: use at least 12 characters."; exit 1; }
read -r -s -p "Same password again: " PW2; echo
[ "$PW" = "$PW2" ] || { echo "They don't match. Nothing changed."; exit 1; }
UID_="$UID_" PW="$PW" python3 -c 'import json,os; print(json.dumps({"localId": os.environ["UID_"], "password": os.environ["PW"]}))' | call accounts:update >/dev/null
# Firebase signs the account out everywhere when its password changes
echo "Done. $EMAIL signs in with the new password, on every device (each one is signed out)."
