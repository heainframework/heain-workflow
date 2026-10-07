package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-workflow/internal/store"
)

type fakePlat struct {
	mu      sync.Mutex
	p5      map[string]string // action id -> result
	nextP5  string            // result of the next proposal
	n       int
	calls   []string
	appOut  map[string]any
	appFail int
	jobs    map[string]heain.JobStatus
	notes   []map[string]any
	key     *ecdsa.PrivateKey
	auditN  int
}

func (f *fakePlat) Propose(_ context.Context, p heain.Proposal) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := "act-" + string(rune('0'+f.n))
	r := f.nextP5
	if r == "" {
		r = heain.ResultWaitingApproval
	}
	f.p5[id] = r
	f.calls = append(f.calls, "propose:"+p.Type+":"+p.Category)
	return heain.PolicyResult{ActionID: id, Type: p.Type, Result: r}, nil
}
func (f *fakePlat) PolicyStatus(_ context.Context, id string) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return heain.PolicyResult{ActionID: id, Result: f.p5[id]}, nil
}
func (f *fakePlat) Call(_ context.Context, cs heain.CallSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "call:"+cs.App+":"+cs.Capability)
	if cs.App == "heain-notify" {
		f.notes = append(f.notes, cs.Body.(map[string]any))
		return 202, nil
	}
	if f.appFail > 0 {
		f.appFail--
		return 0, errors.New("connection refused")
	}
	b, _ := json.Marshal(f.appOut)
	_ = json.Unmarshal(b, cs.Out)
	return 200, nil
}
func (f *fakePlat) Submit(_ context.Context, r heain.JobRequest) (heain.Ticket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "submit:"+r.Capability+":"+string(r.Payload))
	f.jobs["t-1"] = heain.JobStatus{TicketID: "t-1", State: heain.JobQueued}
	return heain.Ticket{TicketID: "t-1"}, nil
}
func (f *fakePlat) Job(_ context.Context, t string) (heain.JobStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[t], nil
}
func (f *fakePlat) ConfirmRetrieval(context.Context, string) error { return nil }
func (f *fakePlat) SignDigest(d []byte) ([]byte, error)            { return ecdsa.SignASN1(rand.Reader, f.key, d) }
func (f *fakePlat) CertDER() []byte                                { return []byte("cert") }
func (f *fakePlat) Audit(context.Context, string, string, map[string]any) error {
	f.mu.Lock()
	f.auditN++
	f.mu.Unlock()
	return nil
}

type kms struct{ m map[string][]byte }

func (k *kms) sealer(_ context.Context, n string) (*heain.Sealer, error) {
	if _, ok := k.m[n]; !ok {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.m[n] = b
	}
	return heain.NewSealer(k.m[n])
}
func (k *kms) destroy(_ context.Context, n string) error { delete(k.m, n); return nil }

type env struct {
	e     *Engine
	p     *fakePlat
	now   time.Time
	mu    sync.Mutex
	hook  *httptest.Server
	hooks []string
}

func (v *env) clock() time.Time { v.mu.Lock(); defer v.mu.Unlock(); return v.now }
func (v *env) advance(d time.Duration) {
	v.mu.Lock()
	v.now = v.now.Add(d)
	v.mu.Unlock()
	v.e.Tick(context.Background())
}

func setup(t *testing.T) *env {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := &env{now: time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC), p: &fakePlat{p5: map[string]string{}, jobs: map[string]heain.JobStatus{}, key: k}}
	v.hook = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Heain-Signature"))
		h := sha256.Sum256(b)
		ok := ecdsa.VerifyASN1(&k.PublicKey, h[:], sig)
		v.mu.Lock()
		v.hooks = append(v.hooks, map[bool]string{true: "signed", false: "unsigned"}[ok])
		v.mu.Unlock()
	}))
	t.Cleanup(v.hook.Close)
	km := &kms{m: map[string][]byte{}}
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"), inside, store.Keys{Sealer: km.sealer, Destroy: km.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	v.e = New(&Engine{Store: st, Plat: v.p, Now: v.clock, Logf: t.Logf, Cfg: Config{PollEvery: time.Second, Location: time.UTC}})
	return v
}

func (v *env) define(t *testing.T, src string) {
	t.Helper()
	ver, err := v.e.SubmitDefinition(context.Background(), []byte(src), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if ver.State == "proposed" {
		v.p.mu.Lock()
		v.p.p5[ver.ActionID] = heain.ResultApproved
		v.p.mu.Unlock()
		v.e.Tick(context.Background())
	}
}

func (v *env) inst(t *testing.T, id string) store.Instance {
	t.Helper()
	in, err := v.e.Store.Instance(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

const purchase = `
id: purchase
title: Purchase
start: {roles: [staff]}
first: review
steps:
  - {id: review, type: task, assign: {role: manager}, outcomes: [approve, reject], fields: [comment], deadline: 1h, notify: ["group:managers"], on: {approve: size, reject: rejected}}
  - {id: size, type: switch, cases: [{var: amount, op: ">", value: 1000, goto: finance}], default: issue}
  - {id: finance, type: p5, action_type: purchase.approve, on: {approved: issue, denied: rejected}}
  - {id: issue, type: app, app: docs, capability: docs.issue.step, path: /v1/issue, next: render, error: rejected}
  - {id: render, type: job, capability: docs.render.step, payload: review, next: erp}
  - {id: erp, type: webhook, url: "HOOK", next: wait}
  - {id: wait, type: timer, wait: 2h, next: tell}
  - {id: tell, type: notify, to: [starter], kind: purchase.done, next: done}
  - {id: done, type: end, status: completed}
  - {id: rejected, type: end, status: rejected}
`

func TestFullRun(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := v.e.Start(ctx, "purchase", nil, "x"); err == nil {
		t.Fatal("no definition yet")
	}
	v.define(t, strings.Replace(purchase, "HOOK", v.hook.URL, 1))
	if v.p.calls[0] != "propose:workflow.activate:KNOWLEDGE_UPDATE" {
		t.Fatalf("activation goes through P5: %v", v.p.calls)
	}
	in, err := v.e.Start(ctx, "purchase", map[string]any{"amount": 5000}, "somchai")
	if err != nil {
		t.Fatal(err)
	}
	v.e.Tick(ctx)
	if got := v.inst(t, in.ID); got.Status != "waiting" || got.Step != "review" {
		t.Fatalf("waiting for review: %+v", got)
	}
	if len(v.p.notes) != 1 || v.p.notes[0]["to"].([]string)[0] != "group:managers" {
		t.Fatalf("task notice: %v", v.p.notes)
	}
	if len(v.e.Inbox("somchai", []string{"staff"})) != 0 {
		t.Fatal("staff do not see a manager task")
	}
	tasks := v.e.Inbox("mali", []string{"manager"})
	if len(tasks) != 1 {
		t.Fatalf("inbox: %v", tasks)
	}
	if _, err := v.e.Complete(ctx, "mali", []string{"manager"}, tasks[0].ID, "maybe", nil); err == nil {
		t.Fatal("unknown outcome")
	}
	if _, err := v.e.Complete(ctx, "mali", []string{"manager"}, tasks[0].ID, "approve", map[string]any{"amount": 1}); err == nil {
		t.Fatal("a field not in the task")
	}
	if _, err := v.e.Claim("mali", []string{"manager"}, tasks[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.Complete(ctx, "dao", []string{"manager"}, tasks[0].ID, "approve", nil); err == nil {
		t.Fatal("claimed by someone else")
	}
	if _, err := v.e.Complete(ctx, "mali", []string{"manager"}, tasks[0].ID, "approve", map[string]any{"comment": "ok"}); err != nil {
		t.Fatal(err)
	}
	v.e.Tick(ctx)
	got := v.inst(t, in.ID)
	if got.Step != "finance" || got.Status != "waiting" {
		t.Fatalf("amount 5000 > 1000: finance (P5): %+v", got)
	}
	// the Approver decides
	v.p.mu.Lock()
	for id, r := range v.p.p5 {
		if r == heain.ResultWaitingApproval {
			v.p.p5[id] = heain.ResultApproved
		}
	}
	v.p.jobs = map[string]heain.JobStatus{}
	v.p.appOut = map[string]any{"outcome": "", "vars": map[string]any{"doc": "PO-1"}}
	v.p.appFail = 1
	v.p.mu.Unlock()
	v.advance(2 * time.Second)
	got = v.inst(t, in.ID)
	if got.Step != "issue" || got.Attempts != 1 {
		t.Fatalf("app failed once: retry: %+v", got)
	}
	v.advance(10 * time.Second)
	got = v.inst(t, in.ID)
	if got.Step != "render" || !strings.Contains(strings.Join(v.p.calls, " "), `submit:docs.render.step:{"by":"mali","fields":{"comment":"ok"},"outcome":"approve"}`) {
		t.Fatalf("job submitted with the review: %+v %v", got, v.p.calls)
	}
	v.p.mu.Lock()
	v.p.jobs["t-1"] = heain.JobStatus{TicketID: "t-1", State: heain.JobCompleted, Output: []byte(`{"pages":3}`)}
	v.p.mu.Unlock()
	v.advance(2 * time.Second)
	got = v.inst(t, in.ID)
	if got.Step != "wait" || len(v.hooks) != 1 || v.hooks[0] != "signed" {
		t.Fatalf("job done, signed webhook, waiting 2h: %+v %v", got, v.hooks)
	}
	if out := got.Vars["render"].(map[string]any)["output"].(map[string]any)["pages"]; out != 3.0 {
		t.Fatalf("job output in the data: %v", got.Vars["render"])
	}
	v.advance(time.Hour)
	if v.inst(t, in.ID).Step != "wait" {
		t.Fatal("still waiting")
	}
	v.advance(time.Hour + time.Second)
	got = v.inst(t, in.ID)
	if got.Status != "completed" {
		t.Fatalf("done: %+v", got)
	}
	last := v.p.notes[len(v.p.notes)-1]
	if last["to"].([]string)[0] != "gateway_user:somchai" || last["ref"] != in.ID || last["kind"] != "purchase.done" {
		t.Fatalf("the starter is told: %v", last)
	}
}

func TestDeadlineDenialAndSchedule(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	src := strings.Replace(purchase, "HOOK", v.hook.URL, 1)
	src = strings.Replace(src, "deadline: 1h,", "deadline: 1h, on_deadline: rejected,", 1)
	v.define(t, src)
	in, _ := v.e.Start(ctx, "purchase", map[string]any{"amount": 5}, "a")
	v.e.Tick(ctx)
	v.advance(61 * time.Minute)
	if got := v.inst(t, in.ID); got.Status != "rejected" {
		t.Fatalf("deadline -> rejected: %+v", got)
	}
	if len(v.e.Inbox("m", []string{"manager"})) != 0 {
		t.Fatal("the overdue task is cancelled")
	}
	// P5 denied
	in2, _ := v.e.Start(ctx, "purchase", map[string]any{"amount": 5000}, "a")
	v.e.Tick(ctx)
	tk := v.e.Inbox("m", []string{"manager"})[0]
	_, _ = v.e.Complete(ctx, "m", []string{"manager"}, tk.ID, "approve", nil)
	v.e.Tick(ctx)
	v.p.mu.Lock()
	for id, r := range v.p.p5 {
		if r == heain.ResultWaitingApproval {
			v.p.p5[id] = heain.ResultDenied
		}
	}
	v.p.mu.Unlock()
	v.advance(2 * time.Second)
	if got := v.inst(t, in2.ID); got.Status != "rejected" || got.Vars["finance"].(map[string]any)["result"] != "denied" {
		t.Fatalf("denied: %+v", got)
	}
	// a schedule: every minute, one start per minute
	v.define(t, "id: daily\ntitle: Daily\nfirst: done\nschedule: \"* * * * *\"\nschedule_vars: {kind: report}\nsteps:\n  - {id: done, type: end, status: completed}\n")
	before := len(v.e.Store.InstanceIDs())
	v.advance(time.Minute)
	v.advance(10 * time.Second) // the same minute: no second start
	if n := len(v.e.Store.InstanceIDs()); n != before+1 {
		t.Fatalf("one scheduled start: %d -> %d", before, n)
	}
	// cancel
	in3, _ := v.e.Start(ctx, "purchase", nil, "a")
	v.e.Tick(ctx)
	if err := v.e.Cancel(ctx, in3.ID, "admin"); err != nil || v.inst(t, in3.ID).Status != "cancelled" {
		t.Fatal("cancel")
	}
	if err := v.e.Cancel(ctx, in3.ID, "admin"); err == nil {
		t.Fatal("cancel twice")
	}
}

func TestVersionsKeepRunning(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	v.define(t, strings.Replace(purchase, "HOOK", v.hook.URL, 1))
	in, _ := v.e.Start(ctx, "purchase", nil, "a")
	v.e.Tick(ctx)
	// version 2 waits for P5, then becomes active; the running instance stays on version 1
	ver, err := v.e.SubmitDefinition(ctx, []byte(strings.Replace(strings.Replace(purchase, "HOOK", v.hook.URL, 1), "title: Purchase", "title: Purchase v2", 1)), "admin")
	if err != nil || ver.State != "proposed" || ver.N != 2 {
		t.Fatalf("v2: %+v %v", ver, err)
	}
	if _, n, _ := v.e.Active("purchase"); n != 1 {
		t.Fatal("v1 stays active until P5 decides")
	}
	v.p.mu.Lock()
	v.p.p5[ver.ActionID] = heain.ResultApproved
	v.p.mu.Unlock()
	v.e.Tick(ctx)
	if d, n, _ := v.e.Active("purchase"); n != 2 || d.Title != "Purchase v2" {
		t.Fatal("v2 active")
	}
	if got := v.inst(t, in.ID); got.Version != 1 {
		t.Fatal("the running instance keeps version 1")
	}
	in2, _ := v.e.Start(ctx, "purchase", nil, "a")
	if in2.Version != 2 {
		t.Fatal("new instances use v2")
	}
	rec, _ := v.e.Store.Def("purchase")
	if rec.Versions[0].State != "retired" {
		t.Fatalf("v1 retired: %+v", rec.Versions[0])
	}
}
