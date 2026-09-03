#!/usr/bin/env bash
# Tier C real, v6 -- definitive + reliable. Corrections carried forward:
#  * probe from inside the cluster (immune to frontend restarts)
#  * wait for 0 RUNNING PODS before probing (no graceful-shutdown false-pass)
#  * SURGICAL channel cleanup: after restoring X, restart only the services that
#    CALL X (their gRPC channel to X went stale), instead of restarting everything.
#  * gate a green baseline before every measurement.
# Real scale-to-zero fault injection on the live Online Boutique; ground truth = HTTP.
set -u
CTX=kind-co-spike
OUT=/tmp/tierc_real_v6.csv
INNER=/tmp/probe_inner.sh
ALL_CALLERS="frontend checkoutservice cartservice recommendationservice"
k(){ kubectl --context "$CTX" "$@"; }
probe(){ k exec -i tierc-probe -- sh < "$INNER" 2>/dev/null; }
pass(){ [ "$1" = 200 ] || [ "$1" = 302 ]; }
green(){ local r; r=$(probe); [ -z "$r" ] && return 1; for c in $r; do pass "$c" || return 1; done; return 0; }
running(){ k get pods -l app=$1 --no-headers 2>/dev/null | grep -c Running; }

# who calls whom (the caller holds an outbound gRPC channel to the callee)
callers_of(){ case "$1" in
  adservice) echo "frontend";; cartservice) echo "frontend checkoutservice";;
  checkoutservice) echo "frontend";; currencyservice) echo "frontend checkoutservice";;
  emailservice) echo "checkoutservice";; paymentservice) echo "checkoutservice";;
  productcatalogservice) echo "frontend checkoutservice recommendationservice";;
  recommendationservice) echo "frontend";; redis-cart) echo "cartservice";;
  shippingservice) echo "frontend checkoutservice";; esac; }

down_confirm(){ k scale deploy/$1 --replicas=0 >/dev/null 2>&1
  for i in $(seq 1 60); do
    [ "$(running $1)" = 0 ] && [ -z "$(k get endpoints $1 -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)" ] && return 0; sleep 1
  done; return 1; }

restart_wait(){ [ -z "$1" ] && return 0; k rollout restart deploy $1 >/dev/null 2>&1
  for s in $1; do k rollout status deploy/$s --timeout=150s >/dev/null 2>&1; done; }

ensure_green(){ for i in $(seq 1 20); do green && return 0; sleep 2; done
  restart_wait "$ALL_CALLERS"; for i in $(seq 1 30); do green && return 0; sleep 2; done; return 1; }

echo "service,base_green,confirmed_down,home,browse,addcart,viewcart,checkout" > "$OUT"
k scale deploy/loadgenerator --replicas=0 >/dev/null 2>&1; sleep 2

for W in adservice cartservice checkoutservice currencyservice emailservice paymentservice productcatalogservice recommendationservice redis-cart shippingservice; do
  if ensure_green; then bg=green; else bg=RED; fi
  if down_confirm $W; then cd=yes; else cd=NO; fi
  sleep 1
  r=$(probe)
  echo "$W,$bg,$cd,$(echo $r | tr ' ' ',')" >> "$OUT"
  echo ">> KILL $W  [base=$bg down=$cd] -> $r"
  k scale deploy/$W --replicas=1 >/dev/null 2>&1
  k rollout status deploy/$W --timeout=150s >/dev/null 2>&1
  restart_wait "$(callers_of $W)"     # surgical: clear stale channels to W
done

k scale deploy/loadgenerator --replicas=1 >/dev/null 2>&1
echo ">> DONE"; column -s, -t "$OUT"
