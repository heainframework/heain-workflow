#!/usr/bin/env bash
# heain-workflow live test 4.6c: a business process with people in it, end to end on a real heain-core node.
#   core G + heain-database + heain-gateway (people) + heain-notify (+ TEST ONLY sinks) + wf-demo (a step app) + heain-workflow.
#  - a workflow-admin submits "purchase" through the gateway; it becomes active only after core's Approver (P5);
#  - a staff member starts it; the manager is told (heain-notify), finds the task in the inbox, claims and approves it;
#  - amount > 1000: core's Approver decides (a p5 step); then wf-demo issues a document (a *.step call), renders it
#    (a core job), the ERP is told (a signed webhook), a timer waits, the starter is told; completed;
#  - a task deadline takes another path; a P5 denial ends as rejected; a new version waits for P5 and only new
#    instances use it; a schedule starts instances; people see only their own; nothing plaintext at rest; audit.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-database, ~/heain-gateway, ~/heain-notify. ~3 min.
# Run from ~/heain-workflow:  bash scripts/live_4_6c.sh
set -uo pipefail
WF=$(cd "$(dirname "$0")/.." && pwd)
DBDIR=${HEAIN_DB_DIR:-$HOME/heain-database}; GWDIR=${HEAIN_GW_DIR:-$HOME/heain-gateway}; NTDIR=${HEAIN_NOTIFY_DIR:-$HOME/heain-notify}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/wf-4-6c
URL=https://127.0.0.1:18000
PUB=https://127.0.0.1:18443
NURL=https://127.0.0.1:19520
EVURL=http://127.0.0.1:19521/v1/core-events
SINKS=$W/sinks.jsonl
API=$PUB/api/heain-workflow
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
approve() { code approver-1 -X POST "$URL/v1/admin/policy/$1/approve"; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$2}" $URL/v1/admin/config/policy/$1 | j "d['action_id']"); [ -n "$id" ] && [ "$(approve $id)" = 200 ]; }
audit() { as admin "$URL/v1/admin/audit?limit=1000&from=${1:-1}"; }
client() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
# people through heain-gateway (a cookie jar each, and its CSRF token)
pub() { local who=$1; shift; curl -sk --noproxy '*' -b "$W/$who.jar" -c "$W/$who.jar" -H 'Content-Type: application/json' "$@"; }
post() { local who=$1; shift; pub "$who" -X POST -H "X-CSRF-Token: $(cat "$W/$who.csrf" 2>/dev/null)" "$@"; }
login() { local out; out=$(pub "$1" -X POST -d "{\"username\":\"$2\",\"password\":\"$3\"${4:+,$4}}" $PUB/auth/login)
  echo "$out" | j "d.get('csrf_token','')" > "$W/$1.csrf"; echo "$out"; }
sinks() { python3 - "$SINKS" "$1" <<'PY' 2>/dev/null
import json,sys,os
rs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()] if os.path.exists(sys.argv[1]) else []
print(sum(1 for r in rs if eval(sys.argv[2])))
PY
}
waitsink() { for k in $(seq 1 ${2:-30}); do [ "$(sinks "$1")" -ge "${3:-1}" ] 2>/dev/null && return 0; sleep 1; done; return 1; }
inst() { pub "$1" "$API/v1/instances/$2"; }
waitst() { for k in $(seq 1 ${4:-40}); do [ "$(inst "$1" "$2" | j "d['status']+'/'+d['step']")" = "$3" ] && return 0; sleep 1; done; return 1; }

echo "== 0. core node G; build everything"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/public.key" -out "$W/public.pem" -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" \
  -ingest-queue-path="$T/data-G/queue.db" -staging-path="$T/data-G/staging.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$WF" && eval "$B go build -o $W/heain-workflow ./cmd/heain-workflow" && eval "$B go build -o $W/wf-demo ./examples/wf-demo" ) \
  && ( cd "$GWDIR" && eval "$B go build -o $W/heain-gateway ./cmd/heain-gateway" ) \
  && ( cd "$NTDIR" && eval "$B go build -o $W/heain-notify ./cmd/heain-notify" && eval "$B go build -o $W/test-sinks ./tools/test-sinks" ) \
  && ok "heain-workflow, wf-demo, heain-gateway, heain-notify and the test sinks build" || { bad "build"; exit 1; }
if [ -n "${HEAIN_DB_BIN:-}" ]; then cp "$HEAIN_DB_BIN" "$W/heain-database"; else ( cd "$DBDIR" && GOFLAGS= go build -o "$W/heain-database" ./cmd/heain-database ); fi
nohup "$W/test-sinks" -smtp 127.0.0.1:18525 -http 127.0.0.1:18526 -out "$SINKS" >> "$W/sinks.log" 2>&1 & echo $! > "$P/sinks.pid"
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1

echo "== 1. the apps start and are admitted"
token heain-database.db1 db1; token heain-gateway.g1 g1; token heain-notify.n1 n1; token wf-demo.d1 d1; token heain-workflow.w1 w1
runapp db1 "$DBDIR/heain-app.yaml" 19460 "$W/state-db1" "$W/heain-database" -external-dialect sqlite
runapp g1 "$GWDIR/heain-app.yaml" 19500 "$W/state-g1" "$W/heain-gateway" -public-listen 127.0.0.1:18443 -public-cert "$W/public.pem" -public-key "$W/public.key" -bootstrap-admin root -routes-refresh 1s
runapp n1 "$NTDIR/heain-app.yaml" 19520 "$W/state-n1" "$W/heain-notify" -admin-callers ops -smtp-addr 127.0.0.1:18525 -smtp-from heain@example.test -smtp-mode plain
runapp d1 "$WF/examples/wf-demo/heain-app.yaml" 19531 "$W/state-d1" "$W/wf-demo"
runapp w1 "$WF/heain-app.yaml" 19530 "$W/state-w1" "$W/heain-workflow" -poll 1s -timezone UTC
for k in $(seq 1 60); do for a in $(pending app.register); do approve $a >/dev/null; done
  n=0; for x in "heain-gateway: active" "heain-notify: active" "wf-demo: active" "heain-workflow: active"; do grep -qh "$x" "$W"/*.log && n=$((n+1)); done; [ $n = 4 ] && break; sleep 1; done
[ $n = 4 ] && ok "heain-database, heain-gateway, heain-notify, wf-demo and heain-workflow admitted" || { bad "start: $n of 4 ($(tail -2 "$W/w1.log"))"; $H stop-all >/dev/null 2>&1; exit 1; }

echo "== 2. core policy: the gateway, its routes to heain-workflow, events to heain-notify (all through P5)"
E='{"app":"heain-workflow","method":'
setpol gateway.apps '["heain-gateway"]' && setpol gateway.exposures "[$E\"PUT\",\"path\":\"/v1/definitions/{id}\",\"roles\":[\"workflow-admin\"]},$E\"GET\",\"path\":\"/v1/definitions/{id}\",\"roles\":[\"workflow-admin\"]},
 $E\"GET\",\"path\":\"/v1/workflows\"},$E\"POST\",\"path\":\"/v1/workflows/{id}/instances\"},$E\"GET\",\"path\":\"/v1/instances\"},$E\"GET\",\"path\":\"/v1/instances/{id}\"},
 $E\"POST\",\"path\":\"/v1/instances/{id}/cancel\",\"roles\":[\"workflow-admin\"]},$E\"GET\",\"path\":\"/v1/tasks\"},$E\"POST\",\"path\":\"/v1/tasks/{id}/claim\"},$E\"POST\",\"path\":\"/v1/tasks/{id}/complete\"}]" \
  && setpol monitor.webhooks "[{\"url\":\"$EVURL\",\"events\":[\"*\"],\"results\":[\"WAITING_APPROVAL\",\"APPROVED_AND_RESUMED\",\"DENIED\"]}]" \
  && ok "gateway.apps, 10 heain-workflow routes, and monitor.webhooks to heain-notify approved" || bad "policy"
read -r _ BOOT < "$W/state-g1/bootstrap-admin.txt"
login root root "$BOOT" '"new_password":"Gateway-Admin-Pass-1"' >/dev/null
mk() { post root -d "{\"id\":\"$1\",\"name\":\"$2\",\"roles\":$3,\"password\":\"$4\"}" $PUB/admin/users | j "d['account']['id']"; }
[ "$(mk wfadmin 'WF Admin' '["workflow-admin"]' Wf-Admin-Pass-1)" = wfadmin ] && [ "$(mk somchai Somchai '["staff"]' Staff-Pass-0001)" = somchai ] \
  && [ "$(mk mali Mali '["staff","manager"]' Manager-Pass-01)" = mali ] && ok "people: wfadmin (workflow-admin), somchai (staff), mali (staff, manager)" || bad "users"
for x in "wfadmin Wf-Admin-Pass-1" "somchai Staff-Pass-0001" "mali Manager-Pass-01"; do set -- $x; login "$1" "$1" "$2" >/dev/null; done
put() { cl ops.c1 -o /dev/null -w '%{http_code}' -X PUT -d "$2" "$NURL$1"; }
[ "$(put /v1/contacts/mali '{"email":"mali@example.test","gateway_user":"mali"}')$(put /v1/contacts/somchai '{"email":"somchai@example.test","gateway_user":"somchai"}')$(put /v1/contacts/ops '{"email":"ops@example.test"}')" = 200200200 ] \
  && [ "$(put /v1/groups/managers '{"members":["mali"]}')$(put /v1/groups/ops-team '{"members":["ops"]}')" = 200200 ] && ok "notify contacts: mali, somchai, ops; groups managers, ops-team" || bad "contacts"
for k in $(seq 1 20); do [ "$(pub wfadmin -o /dev/null -w '%{http_code}' $API/v1/workflows)" = 200 ] && break; sleep 1; done

echo "== 3. definitions: submitted by a workflow-admin, active only after P5"
cat > "$W/purchase.yaml" <<EOF
id: purchase
title: Purchase request
start: {roles: [staff]}
first: review
steps:
  - {id: review, type: task, title: Review the purchase, assign: {role: manager}, outcomes: [approve, reject], fields: [comment], notify: ["group:managers"], on: {approve: size, reject: rejected}}
  - {id: size, type: switch, cases: [{var: amount, op: ">", value: 1000, goto: finance}], default: issue}
  - {id: finance, type: p5, action_type: purchase.approve, on: {approved: issue, denied: rejected}}
  - {id: issue, type: app, app: wf-demo, capability: docs.issue.step, path: /v1/issue, next: render}
  - {id: render, type: job, capability: docs.render.step, payload: review, next: erp}
  - {id: erp, type: webhook, url: "http://127.0.0.1:18526/hook/erp", next: wait}
  - {id: wait, type: timer, wait: 3s, next: tell}
  - {id: tell, type: notify, to: [starter], kind: purchase.done, next: done}
  - {id: done, type: end, status: completed}
  - {id: rejected, type: end, status: rejected}
EOF
cat > "$W/leave.yaml" <<'EOF'
id: leave
title: Leave request
start: {roles: [staff]}
first: approve
steps:
  - {id: approve, type: task, assign: {role: manager}, outcomes: [ok], deadline: 6s, on_deadline: expired, next: done}
  - {id: done, type: end, status: completed}
  - {id: expired, type: end, status: expired}
EOF
printf 'id: tick\ntitle: Tick\nfirst: done\nschedule: "* * * * *"\nschedule_vars: {kind: tick}\nsteps:\n  - {id: done, type: end, status: completed}\n' > "$W/tick.yaml"
[ "$(pub somchai -o /dev/null -w '%{http_code}' -X PUT -H "X-CSRF-Token: $(cat "$W/somchai.csrf")" --data-binary @"$W/purchase.yaml" $API/v1/definitions/purchase)" = 403 ] && ok "staff cannot submit a definition (the gateway refuses)" || bad "staff submit"
r=$(pub wfadmin -X PUT -H "X-CSRF-Token: $(cat "$W/wfadmin.csrf")" --data-binary @"$W/purchase.yaml" $API/v1/definitions/purchase)
A1=$(echo "$r" | j "d['action_id']")
[ "$(echo "$r" | j "(d['version'],d['state'])")" = "(1, 'proposed')" ] && [ -n "$A1" ] && ok "wfadmin submitted purchase v1: proposed, P5 $A1" || bad "submit: $r"
for f in leave tick; do r=$(pub wfadmin -X PUT -H "X-CSRF-Token: $(cat "$W/wfadmin.csrf")" --data-binary @"$W/$f.yaml" $API/v1/definitions/$f); eval "A_$f=$(echo "$r" | j "d['action_id']")"; done
[ "$(pub wfadmin -o /dev/null -w '%{http_code}' -X PUT -H "X-CSRF-Token: $(cat "$W/wfadmin.csrf")" --data-binary 'id: purchase
first: x
steps: []' $API/v1/definitions/purchase)" = 400 ] && ok "an invalid definition is refused" || bad "invalid def"
[ "$(pub somchai $API/v1/workflows | j "[w['id'] for w in d['workflows']]")" = "[]" ] && ok "not active yet: somchai sees no workflow" || bad "active early"
waitsink "r['to']=='ops@example.test' and '$A1' in r['body']" 20 && ok "ops-team was told by heain-notify that workflow.activate waits for an Approver" || bad "activate notice"
for a in $A1 $A_leave $A_tick; do approve $a >/dev/null; done
for k in $(seq 1 15); do [ "$(pub somchai $API/v1/workflows | j "sorted(w['id'] for w in d['workflows'])")" = "['leave', 'purchase']" ] && break; sleep 1; done
[ "$(pub somchai $API/v1/workflows | j "sorted(w['id'] for w in d['workflows'])")" = "['leave', 'purchase']" ] && ok "approver-1 approved: somchai (staff) may start purchase and leave" || bad "after approval: $(pub somchai $API/v1/workflows)"

echo "== 4. a purchase: task, P5, app step, job, webhook, timer, notice"
r=$(post somchai -d '{"vars":{"amount":5000,"item":"laptops"}}' $API/v1/workflows/purchase/instances); I1=$(echo "$r" | j "d['instance']")
[ -n "$I1" ] && ok "somchai started purchase ($I1, amount 5000)" || bad "start: $r"
waitst somchai "$I1" "waiting/review" 15 && ok "it waits for a manager's review" || bad "review: $(inst somchai $I1 | head -c 300)"
waitsink "r['to']=='mali@example.test' and 'Review the purchase' in r['body']" 20 && ok "mali (managers) was told by email: a task" || bad "task notice"
[ "$(pub somchai $API/v1/tasks | j "len(d['tasks'])")" = 0 ] && ok "somchai's inbox is empty (staff, not manager)" || bad "somchai inbox"
TK=$(pub mali $API/v1/tasks | j "[t['id'] for t in d['tasks'] if t['instance']=='$I1'][0]")
[ -n "$TK" ] && [ "$(post mali $API/v1/tasks/$TK/claim | j "d['status']")" = claimed ] && ok "mali found it in her inbox and claimed it" || bad "claim"
[ "$(post mali -d '{"outcome":"approve","data":{"amount":1}}' -o /dev/null -w '%{http_code}' $API/v1/tasks/$TK/complete)" = 400 ] && ok "a field that is not part of the task is refused" || bad "field check"
[ "$(post mali -d '{"outcome":"approve","data":{"comment":"SECRET-COMMENT-OK"}}' $API/v1/tasks/$TK/complete | j "d['outcome']")" = approve ] && ok "mali approved (with a comment)" || bad "complete"
waitst somchai "$I1" "waiting/finance" 15 && ok "amount 5000 > 1000: core's Approver decides (a p5 step)" || bad "finance: $(inst somchai $I1 | j "d['status'],d['step']")"
PA=$(as approver-1 $URL/v1/admin/policy/pending | j "[x['ID'] for x in d['actions'] if x['Type']=='purchase.approve'][0]")
[ -n "$PA" ] && [ "$(approve $PA)" = 200 ] && ok "approver-1 approved purchase.approve ($PA)" || bad "p5"
waitst somchai "$I1" "completed/done" 40 && ok "then: wf-demo issued the document, rendered it as a core job, the ERP was told, 3 s timer, done" || bad "run: $(inst somchai $I1 | j "d['status'],d['step'],d['history'][-1]")"
v=$(inst somchai $I1 | j "(d['vars']['issue']['vars']['doc'],d['vars']['render']['output']['pages'],d['vars']['render']['output']['rendered_for'],d['version'])")
[ "$v" = "('PO-0001', 3, 'mali', 1)" ] && ok "the data: document PO-0001; the job rendered 3 pages for mali's review; version 1" || bad "vars: $v"
waitsink "r['kind']=='hook' and r['to']=='/hook/erp' and '$I1' in r['body']" 10 && ok "the ERP webhook got the instance" || bad "erp hook"
python3 - "$SINKS" "$I1" "$W" <<'PY'
import json,sys,base64
rs=[json.loads(l) for l in open(sys.argv[1]) if 'hook/erp' in l and sys.argv[2] in l]
if not rs: sys.exit(0)
r=rs[0]
open(sys.argv[3]+"/erp.body","w").write(r['body']); open(sys.argv[3]+"/erp.sig","wb").write(base64.b64decode(r['headers']['X-Heain-Signature'])); open(sys.argv[3]+"/erp.der","wb").write(base64.b64decode(r['headers']['X-Heain-Cert']))
PY
openssl x509 -inform der -in "$W/erp.der" -pubkey -noout > "$W/erp.pub" 2>/dev/null
[ "$(openssl dgst -sha256 -verify "$W/erp.pub" -signature "$W/erp.sig" "$W/erp.body" 2>&1)" = "Verified OK" ] && openssl x509 -inform der -in "$W/erp.der" -noout -subject | grep -q heain-workflow.w1 \
  && ok "it is signed by heain-workflow.w1's app key" || bad "erp signature"
waitsink "r['to']=='somchai@example.test' and '$I1' in r['body']" 15 && ok "somchai (the starter) was told it is done" || bad "done notice"

echo "== 5. a deadline, a denial, a cancel"
r=$(post somchai -d '{"vars":{}}' $API/v1/workflows/leave/instances); I2=$(echo "$r" | j "d['instance']")
waitst somchai "$I2" "expired/expired" 20 && ok "leave: nobody acted within 6 s: the deadline took the expired path" || bad "deadline: $(inst somchai $I2 | j "d['status'],d['step']")"
[ "$(pub mali $API/v1/tasks | j "len([t for t in d['tasks'] if t['instance']=='$I2'])")" = 0 ] && ok "its task left the inbox" || bad "task still there"
r=$(post somchai -d '{"vars":{"amount":9000}}' $API/v1/workflows/purchase/instances); I3=$(echo "$r" | j "d['instance']")
waitst somchai "$I3" "waiting/review" 15; TK=$(pub mali $API/v1/tasks | j "[t['id'] for t in d['tasks'] if t['instance']=='$I3'][0]")
post mali -d '{"outcome":"approve"}' $API/v1/tasks/$TK/complete >/dev/null
waitst somchai "$I3" "waiting/finance" 15
PA=$(as approver-1 $URL/v1/admin/policy/pending | j "[x['ID'] for x in d['actions'] if x['Type']=='purchase.approve'][0]")
[ "$(code approver-1 -X POST -d '{"reason":"over budget"}' $URL/v1/admin/policy/$PA/reject)" = 200 ] && waitst somchai "$I3" "rejected/rejected" 15 && ok "a second purchase: the Approver rejected it: rejected" || bad "denial"
r=$(post somchai -d '{"vars":{"amount":10}}' $API/v1/workflows/purchase/instances); I4=$(echo "$r" | j "d['instance']")
waitst somchai "$I4" "waiting/review" 15
[ "$(post somchai -o /dev/null -w '%{http_code}' $API/v1/instances/$I4/cancel)" = 403 ] && [ "$(post wfadmin $API/v1/instances/$I4/cancel | j "d['status']")" = cancelled ] && ok "only a workflow-admin cancels an instance" || bad "cancel"

echo "== 6. a new version waits for P5; running instances keep theirs"
r=$(post somchai -d '{"vars":{"amount":10}}' $API/v1/workflows/purchase/instances); I5=$(echo "$r" | j "d['instance']")
sed 's/title: Purchase request/title: Purchase request v2/' "$W/purchase.yaml" > "$W/purchase2.yaml"
r=$(pub wfadmin -X PUT -H "X-CSRF-Token: $(cat "$W/wfadmin.csrf")" --data-binary @"$W/purchase2.yaml" $API/v1/definitions/purchase); A2=$(echo "$r" | j "d['action_id']")
[ "$(pub somchai $API/v1/workflows | j "[w['version'] for w in d['workflows'] if w['id']=='purchase']")" = "[1]" ] && ok "v2 proposed; v1 stays active" || bad "v2 early"
approve $A2 >/dev/null
for k in $(seq 1 15); do [ "$(pub somchai $API/v1/workflows | j "[w['version'] for w in d['workflows'] if w['id']=='purchase']")" = "[2]" ] && break; sleep 1; done
I6=$(post somchai -d '{"vars":{"amount":10}}' $API/v1/workflows/purchase/instances | j "d['instance']")
[ "$(inst somchai $I5 | j "d['version']")" = 1 ] && [ "$(inst somchai $I6 | j "d['version']")" = 2 ] && ok "after P5: new instances use v2, the running one keeps v1" || bad "versions"

echo "== 7. a schedule; who sees what; at rest; the audit"
for k in $(seq 1 75); do [ "$(pub wfadmin $API/v1/instances | j "len([x for x in d['instances'] if x['workflow']=='tick'])")" -ge 1 ] 2>/dev/null && break; sleep 1; done
[ "$(pub wfadmin $API/v1/instances | j "[x['starter'] for x in d['instances'] if x['workflow']=='tick'][:1]")" = "['schedule']" ] && ok "the schedule (every minute) started tick" || bad "schedule"
[ "$(pub somchai -o /dev/null -w '%{http_code}' $API/v1/instances/$I1)" = 200 ] && [ "$(pub wfadmin -o /dev/null -w '%{http_code}' $API/v1/instances/$I1)" = 200 ] \
  && [ "$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' $API/v1/instances/$I1)" = 401 ] && ok "the starter and an admin see the instance; no one unsigned" || bad "visibility"
[ "$(mk nid Nid '["staff"]' Staff-Pass-0002)" = nid ] && login nid nid Staff-Pass-0002 >/dev/null
[ "$(pub nid -o /dev/null -w '%{http_code}' $API/v1/instances/$I1)" = 404 ] && [ "$(pub nid $API/v1/instances | j "len(d['instances'])")" = 0 ] && ok "another staff member sees none of them" || bad "other staff"
s=$(python3 -c "import sys;b=open(sys.argv[1],'rb').read();print(sum(b.count(x.encode()) for x in sys.argv[2:]))" "$W/state-w1/workflow.db" SECRET-COMMENT laptops somchai PO-0001)
[ "$s" = 0 ] && ok "workflow.db holds no data, comment, name or document number in plaintext" || bad "plaintext: $s"
n=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='workflow.task' and (x['event']['Detail']['detail'] or {}).get('user')=='mali')")
m=$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='workflow.run' and x['event']['Result'] in ('started','ended'))")
[ "${n:-0}" -ge 3 ] && [ "${m:-0}" -ge 8 ] && ok "core's audit: mali's task actions ($n, with her signed assertion) and instances started/ended ($m)" || bad "audit: $n $m"
audit | grep -q "SECRET-COMMENT\|laptops" && bad "data in the audit" || ok "no instance data in the audit chain"
[ "$(as admin $URL/v1/admin/audit/verify | j "d['ok']")" = True ] && ok "audit chain verifies" || bad "verify"

echo "== cleanup"
kill "$(cat "$P/sinks.pid")" 2>/dev/null
$H stop-all >/dev/null 2>&1
for f in db1 g1 n1 d1 w1; do [ -f "$P/$f.pid" ] && kill "$(cat "$P/$f.pid")" 2>/dev/null; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
