#!/usr/bin/env bash
# Points PlutoScan checkout (createCheckoutSession) at the right Stripe price. Run in Cloud Shell:
#   bash <(curl -s https://raw.githubusercontent.com/ogpoopdogg/usage/main/scripts/fix-plutoscan-price.sh)
# 1. Asks for the price ID and checks it with the Stripe key checkout uses: it must exist, be
#    active and be live. Nothing changes if it isn't.
# 2. Asks "yes", then sets STRIPE_PRICE_ID on the running checkout service (Cloud Run, the service
#    behind the function). No code or other setting changes.
# 3. Shows whether that Stripe account has a webhook to stripeWebhook, and which Stripe key kind the
#    site uses. Never prints more than the first 8 characters of a key.
set -u
P=plutoscan
R=us-central1
FN=createCheckoutSession
J=$(mktemp)
trap 'rm -f "$J"; unset K' EXIT

echo "=== 1. Check the price"
read -rp "Paste your full price ID (starts with price_) and press Enter: " PRICE
PRICE=$(printf '%s' "$PRICE" | tr -d '[:space:]')
case "$PRICE" in price_*) ;; *) echo "That doesn't start with price_. Nothing changed."; exit 1 ;; esac

gcloud functions describe $FN --region $R --project $P --format=json > "$J" || { echo "Could not read $FN. Nothing changed."; exit 1; }
SVC=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("serviceConfig",{}).get("service","").split("/")[-1])' "$J")
gcloud run services describe "$SVC" --region $R --project $P --format=json > "$J" || { echo "Could not read the checkout service. Nothing changed."; exit 1; }
read -r OLD V <<<"$(python3 -c 'import json,sys
e=json.load(open(sys.argv[1]))["spec"]["template"]["spec"]["containers"][0].get("env",[])
p=[x.get("value","") for x in e if x["name"]=="STRIPE_PRICE_ID"]
k=[x.get("valueFrom",{}).get("secretKeyRef",{}).get("key","latest") for x in e if x["name"]=="STRIPE_SECRET_KEY"]
print((p or ["(none)"])[0], (k or ["latest"])[0])' "$J")"
echo "Checkout uses price $OLD now, and STRIPE_SECRET_KEY version $V."

K=$(gcloud secrets versions access "$V" --secret STRIPE_SECRET_KEY --project $P) || { echo "Could not read the key. Nothing changed."; exit 1; }
echo "That key starts ${K:0:8}"
curl -s -u "$K:" "https://api.stripe.com/v1/prices/$PRICE?expand%5B%5D=product" > "$J"
OK=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
if "error" in d: print("NO Stripe says: "+d["error"].get("message","error")); sys.exit()
pr=d.get("product") or {}
name=pr.get("name","?") if isinstance(pr,dict) else pr
amt="%.2f %s"%(d.get("unit_amount",0)/100, str(d.get("currency","")).upper())
mode="LIVE" if d.get("livemode") else "TEST"
if not d.get("active"): print("NO The price is archived: "+name+", "+amt); sys.exit()
if not d.get("livemode"): print("NO The price is a TEST price: "+name+", "+amt); sys.exit()
print("YES "+name+", "+amt+", "+mode+" mode, active")' "$J")
echo "Price check: ${OK#* }"
case "$OK" in YES*) ;; *) echo "Nothing changed. Make sure the price is in the same Stripe account and mode as the key (starts ${K:0:8})."; exit 1 ;; esac

echo; echo "=== 2. Switch checkout to this price"
read -rp "Type yes and press Enter to switch checkout from $OLD to $PRICE: " GO
[ "$GO" = "yes" ] || { echo "Nothing changed."; exit 1; }
gcloud run services update "$SVC" --region $R --project $P --update-env-vars "STRIPE_PRICE_ID=$PRICE" --quiet && echo "Done: checkout now sells $PRICE." || { echo "The switch failed: send Claude the red lines above."; exit 1; }

echo; echo "=== 3. Two more things that must match the same Stripe account"
curl -s -u "$K:" "https://api.stripe.com/v1/webhook_endpoints?limit=100" > "$J"
python3 -c 'import json,sys
d=json.load(open(sys.argv[1])).get("data",[])
w=[x for x in d if "stripeWebhook" in x.get("url","")]
print("Webhook to stripeWebhook in this Stripe account: " + ("yes ("+w[0].get("status","?")+")" if w else "NO - paid customers will not get the course until you add it"))' "$J"
unset K
SITE=$(curl -s https://plutoscan.com/ https://plutoscan.com/plutoscan-auth.js | grep -o 'pk_\(live\|test\)_' | sort -u | tr '\n' ' ')
echo "Key kind the website uses: ${SITE:-not found}"
echo
echo "=== Finished. Next time you deploy your PlutoScan functions, set STRIPE_PRICE_ID=$PRICE in functions/.env.plutoscan too, or the deploy puts the old one back."
