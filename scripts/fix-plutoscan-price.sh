#!/usr/bin/env bash
# Points PlutoScan checkout (createCheckoutSession) at the right Stripe price. Run in Cloud Shell:
#   bash <(curl -s https://raw.githubusercontent.com/ogpoopdogg/usage/main/scripts/fix-plutoscan-price.sh)
# 1. Asks for the price ID and checks it with the Stripe key checkout uses: it must exist, be
#    active and be live. Nothing changes if it isn't.
# 2. Asks "yes", then changes STRIPE_PRICE_ID and rebuilds createCheckoutSession only:
#    a. if your PlutoScan code is in this Cloud Shell (functions/.env.plutoscan): edits that file
#       and deploys createCheckoutSession from it with Firebase;
#    b. otherwise: asks Google to rebuild createCheckoutSession from the code it already has, with
#       only STRIPE_PRICE_ID changed. (Changing the running service directly doesn't work when its
#       old build image has been cleaned up.)
#    If the rebuild fails, the checkout that is running now keeps running.
# 3. Shows whether that Stripe account has a webhook to stripeWebhook, and which Stripe key kind the
#    site uses. Never prints more than the first 8 characters of a key.
set -u
P=plutoscan
R=us-central1
FN=createCheckoutSession
API=https://cloudfunctions.googleapis.com/v2
J=$(mktemp)
B=$(mktemp)
trap 'rm -f "$J" "$B"; unset K' EXIT

echo "=== 1. Check the price"
read -rp "Paste your full price ID (starts with price_) and press Enter: " PRICE
PRICE=$(printf '%s' "$PRICE" | tr -d '[:space:]')
case "$PRICE" in price_*) ;; *) echo "That doesn't start with price_. Nothing changed."; exit 1 ;; esac

TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer $TOKEN" "$API/projects/$P/locations/$R/functions/$FN" > "$J"
read -r OLD V SB SO <<<"$(python3 -c 'import json,sys
f=json.load(open(sys.argv[1])); s=f.get("serviceConfig",{})
p=s.get("environmentVariables",{}).get("STRIPE_PRICE_ID","(none)")
k=[x.get("version","latest") for x in s.get("secretEnvironmentVariables",[]) if x.get("key")=="STRIPE_SECRET_KEY"]
src=f.get("buildConfig",{}).get("source",{}).get("storageSource",{})
print(p, (k or ["latest"])[0], src.get("bucket","-"), src.get("object","-"))' "$J")"
[ -n "${OLD:-}" ] || { echo "Could not read $FN. Nothing changed."; exit 1; }
echo "Checkout uses price $OLD now, and STRIPE_SECRET_KEY version $V."

K=$(gcloud secrets versions access "$V" --secret STRIPE_SECRET_KEY --project $P) || { echo "Could not read the key. Nothing changed."; exit 1; }
echo "That key starts ${K:0:8}"
curl -s -u "$K:" "https://api.stripe.com/v1/prices/$PRICE?expand%5B%5D=product" > "$B"
OK=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
if "error" in d: print("NO Stripe says: "+d["error"].get("message","error")); sys.exit()
pr=d.get("product") or {}
name=pr.get("name","?") if isinstance(pr,dict) else pr
amt="%.2f %s"%(d.get("unit_amount",0)/100, str(d.get("currency","")).upper())
if not d.get("active"): print("NO The price is archived: "+name+", "+amt); sys.exit()
if not d.get("livemode"): print("NO The price is a TEST price: "+name+", "+amt); sys.exit()
print("YES "+name+", "+amt+", LIVE mode, active")' "$B")
echo "Price check: ${OK#* }"
case "$OK" in YES*) ;; *) echo "Nothing changed. Make sure the price is in the same Stripe account and mode as the key (starts ${K:0:8})."; exit 1 ;; esac

echo; echo "=== 2. Switch checkout to this price"
F=$(find ~ -maxdepth 5 -path '*/functions/.env.plutoscan' -not -path '*/node_modules/*' 2>/dev/null | head -1)
if [ -n "$F" ]; then
D=$(dirname "$(dirname "$F")")
echo "Found your PlutoScan code in $D (settings file last changed $(date -r "$F" '+%Y-%m-%d'))."
echo "This edits that file and deploys createCheckoutSession from that folder."
read -rp "Type yes and press Enter to switch checkout from $OLD to $PRICE: " GO
[ "$GO" = "yes" ] || { echo "Nothing changed."; exit 1; }
if grep -q '^STRIPE_PRICE_ID=' "$F"; then sed -i "s/^STRIPE_PRICE_ID=.*/STRIPE_PRICE_ID=$PRICE/" "$F"; else echo "STRIPE_PRICE_ID=$PRICE" >> "$F"; fi
echo "File updated."
(cd "$D/functions" && { npm ci --no-audit --no-fund >/dev/null 2>&1 || npm install --no-audit --no-fund >/dev/null; })
(cd "$D" && npx -y firebase-tools deploy --only functions:$FN --project $P) && echo "Done: checkout now sells $PRICE." || { echo "The deploy failed: send Claude the red lines above. The old checkout keeps running."; exit 1; }
else
echo "Your PlutoScan code isn't in this Cloud Shell, so Google will rebuild checkout from the code it already has."
if [ "$SB" = "-" ] || ! gsutil -q stat "gs://$SB/$SO" 2>/dev/null; then
echo "Google no longer has checkout's code (gs://$SB/$SO), so it can't rebuild it. Nothing changed."
echo "This needs your PlutoScan functions folder: set STRIPE_PRICE_ID=$PRICE in functions/.env.plutoscan and run: firebase deploy --only functions:$FN --project $P"
exit 1
fi
read -rp "Type yes and press Enter to switch checkout from $OLD to $PRICE: " GO
[ "$GO" = "yes" ] || { echo "Nothing changed."; exit 1; }
python3 -c 'import json,sys
f=json.load(open(sys.argv[1])); env=dict(f.get("serviceConfig",{}).get("environmentVariables",{}))
env["STRIPE_PRICE_ID"]=sys.argv[2]
json.dump({"serviceConfig":{"environmentVariables":env}}, open(sys.argv[3],"w"))' "$J" "$PRICE" "$B"
OP=$(curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data @"$B" "$API/projects/$P/locations/$R/functions/$FN?updateMask=serviceConfig.environmentVariables" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("name") or "ERROR "+json.dumps(d.get("error",d))[:400])')
case "$OP" in ERROR*) echo "Google refused: ${OP#ERROR }"; echo "Nothing changed. Send Claude this line."; exit 1 ;; esac
echo "Rebuilding checkout (about 2 to 4 minutes)..."
for i in $(seq 1 40); do
sleep 15
TOKEN=$(gcloud auth print-access-token)
S=$(curl -s -H "Authorization: Bearer $TOKEN" "$API/$OP" | python3 -c 'import json,sys; d=json.load(sys.stdin)
print("WAIT" if not d.get("done") else ("FAIL "+json.dumps(d["error"])[:400] if "error" in d else "OK"))')
case "$S" in OK) echo "Done: checkout now sells $PRICE."; break ;; FAIL*) echo "The rebuild failed: ${S#FAIL }"; echo "The old checkout keeps running. Send Claude this line."; exit 1 ;; esac
printf '.'
done
[ "$S" = "OK" ] || { echo; echo "Still building after 10 minutes; check Functions in the Firebase console, or run this again later."; exit 1; }
fi

echo; echo "=== 3. Two more things that must match the same Stripe account"
curl -s -u "$K:" "https://api.stripe.com/v1/webhook_endpoints?limit=100" > "$B"
python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("data",[])
w=[x for x in d if "stripeWebhook" in x.get("url","")]
print("Webhook to stripeWebhook in this Stripe account: " + ("yes ("+w[0].get("status","?")+")" if w else "NO - paid customers will not get the course until you add it"))' "$B"
unset K
SITE=$(curl -s https://plutoscan.com/ https://plutoscan.com/plutoscan-auth.js | grep -o 'pk_\(live\|test\)_' | sort -u | tr '\n' ' ')
echo "Key kind the website uses: ${SITE:-not found}"
echo
[ -z "$F" ] && echo "=== Finished. Next time you deploy your PlutoScan functions, set STRIPE_PRICE_ID=$PRICE in functions/.env.plutoscan too, or the deploy puts the old one back." || echo "=== Finished."
