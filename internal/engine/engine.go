// Package engine runs workflow instances (author decisions 2026-10-07):
// people's tasks, core's Approver (P5), apps that opt in (*.step), core jobs,
// signed webhooks, heain-notify messages, timers, deadlines and schedules.
// Definitions are activated through P5; a running instance keeps its version.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-workflow/internal/def"
	"github.com/heainframework/heain-workflow/internal/store"
)

// AdminRole may submit definitions and cancel instances (through heain-gateway).
const AdminRole = "workflow-admin"

// Platform is what the engine needs from heain-core (through heain-sdk).
type Platform interface {
	Propose(ctx context.Context, p heain.Proposal) (heain.PolicyResult, error)
	PolicyStatus(ctx context.Context, actionID string) (heain.PolicyResult, error)
	Call(ctx context.Context, cs heain.CallSpec) (int, error)
	Submit(ctx context.Context, r heain.JobRequest) (heain.Ticket, error)
	Job(ctx context.Context, ticket string) (heain.JobStatus, error)
	ConfirmRetrieval(ctx context.Context, ticket string) error
	SignDigest(digest []byte) ([]byte, error)
	CertDER() []byte
	Audit(ctx context.Context, capability, outcome string, d map[string]any) error
}

// Config tunes the engine.
type Config struct {
	AdminCallers []string // apps that may manage definitions without a person
	NotifyApp    string   // default heain-notify
	Location     *time.Location
	PollEvery    time.Duration // P5 decisions and jobs
	MaxAttempts  int           // automatic steps
	HTTP         *http.Client  // webhooks
}

// Engine runs workflows.
type Engine struct {
	Cfg   Config
	Store *store.Store
	Plat  Platform
	Logf  func(string, ...any)
	Now   func() time.Time

	mu   sync.Mutex                // instances, tasks, definition records
	dmu  sync.Mutex                // the parsed definitions cache
	defs map[string]def.Definition // "<id>@<n>"
	kick chan struct{}
}

// New prepares an engine.
func New(e *Engine) *Engine {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Logf == nil {
		e.Logf = func(string, ...any) {}
	}
	if e.Cfg.NotifyApp == "" {
		e.Cfg.NotifyApp = "heain-notify"
	}
	if e.Cfg.Location == nil {
		e.Cfg.Location = time.Local
	}
	if e.Cfg.PollEvery <= 0 {
		e.Cfg.PollEvery = 3 * time.Second
	}
	if e.Cfg.MaxAttempts <= 0 {
		e.Cfg.MaxAttempts = 3
	}
	if e.Cfg.HTTP == nil {
		e.Cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	e.defs = map[string]def.Definition{}
	e.kick = make(chan struct{}, 1)
	return e
}

func (e *Engine) wake() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *Engine) audit(ctx context.Context, cap, outcome string, d map[string]any) {
	// its own trace: a served call already has exactly one formal record
	// (spec 05 C5); the request's trace is kept as cause_trace
	if d == nil {
		d = map[string]any{}
	}
	if t := heain.TraceID(ctx); t != "" {
		d["cause_trace"] = t
	}
	ctx = heain.WithTrace(ctx, heain.NewID(), "")
	if err := e.Plat.Audit(ctx, cap, outcome, d); err != nil {
		e.Logf("heain-workflow: audit %s %s: %v", cap, outcome, err)
	}
}

// ---- definitions ----

// definition returns the parsed definition of id at version n.
func (e *Engine) definition(id string, n int) (def.Definition, error) {
	k := fmt.Sprintf("%s@%d", id, n)
	e.dmu.Lock()
	d, ok := e.defs[k]
	e.dmu.Unlock()
	if ok {
		return d, nil
	}
	rec, err := e.Store.Def(id)
	if err != nil {
		return def.Definition{}, err
	}
	for _, v := range rec.Versions {
		if v.N == n {
			d, err := def.Parse([]byte(v.Source))
			if err != nil {
				return def.Definition{}, err
			}
			e.dmu.Lock()
			e.defs[k] = d
			e.dmu.Unlock()
			return d, nil
		}
	}
	return def.Definition{}, store.ErrNotFound
}

// SubmitDefinition stores a new version and asks P5 to activate it.
func (e *Engine) SubmitDefinition(ctx context.Context, src []byte, by string) (store.Version, error) {
	d, err := def.Parse(src)
	if err != nil {
		return store.Version{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, err := e.Store.Def(d.ID)
	if errors.Is(err, store.ErrNotFound) {
		rec = store.DefRecord{ID: d.ID}
	} else if err != nil {
		return store.Version{}, err
	}
	h := sha256.Sum256(src)
	v := store.Version{N: len(rec.Versions) + 1, Source: string(src), SHA256: hex.EncodeToString(h[:]), By: by, At: e.Now().UTC(), State: "proposed"}
	r, err := e.Plat.Propose(ctx, heain.Proposal{Type: "workflow.activate", Category: heain.CategoryKnowledgeUpdate,
		Data: map[string]any{"workflow": d.ID, "version": v.N, "sha256": v.SHA256, "submitted_by": by, "steps": len(d.Steps)}})
	if err != nil {
		return store.Version{}, fmt.Errorf("P5: %w", err)
	}
	v.ActionID = r.ActionID
	rec.Versions = append(rec.Versions, v)
	switch {
	case r.Allowed():
		e.activate(&rec, v.N)
	case r.Result == heain.ResultDenied:
		rec.Versions[len(rec.Versions)-1].State = "denied"
	}
	if err := e.Store.PutDef(rec); err != nil {
		return store.Version{}, err
	}
	return rec.Versions[len(rec.Versions)-1], nil
}

func (e *Engine) activate(rec *store.DefRecord, n int) {
	for i := range rec.Versions {
		switch {
		case rec.Versions[i].N == n:
			rec.Versions[i].State, rec.Versions[i].DecidedAt = "active", e.Now().UTC()
		case rec.Versions[i].State == "active":
			rec.Versions[i].State = "retired"
		}
	}
	rec.Active = n
	if rec.LastScheduled.IsZero() {
		rec.LastScheduled = e.Now().Truncate(time.Minute)
	}
}

// pollDefinitions follows proposed versions until P5 decides.
func (e *Engine) pollDefinitions(ctx context.Context) {
	for _, rec := range e.Store.Defs() {
		for _, v := range rec.Versions {
			if v.State != "proposed" || v.ActionID == "" {
				continue
			}
			r, err := e.Plat.PolicyStatus(ctx, v.ActionID)
			if err != nil || r.Waiting() {
				continue
			}
			e.mu.Lock()
			cur, err := e.Store.Def(rec.ID)
			if err == nil {
				if r.Allowed() {
					e.activate(&cur, v.N)
				} else {
					for i := range cur.Versions {
						if cur.Versions[i].N == v.N {
							cur.Versions[i].State, cur.Versions[i].DecidedAt = "denied", e.Now().UTC()
						}
					}
				}
				_ = e.Store.PutDef(cur)
			}
			e.mu.Unlock()
			e.audit(ctx, "workflow.define", "version_"+map[bool]string{true: "activated", false: "denied"}[r.Allowed()],
				map[string]any{"workflow": rec.ID, "version": v.N, "action_id": v.ActionID})
		}
	}
}

// Active returns the active definition of id.
func (e *Engine) Active(id string) (def.Definition, int, error) {
	rec, err := e.Store.Def(id)
	if err != nil {
		return def.Definition{}, 0, err
	}
	if rec.Active == 0 {
		return def.Definition{}, 0, fmt.Errorf("workflow %s has no active version (waiting for P5?)", id)
	}
	d, err := e.definition(id, rec.Active)
	return d, rec.Active, err
}

// ---- instances ----

// Start begins an instance of id's active version.
func (e *Engine) Start(ctx context.Context, id string, vars map[string]any, starter string) (store.Instance, error) {
	d, n, err := e.Active(id)
	if err != nil {
		return store.Instance{}, err
	}
	if vars == nil {
		vars = map[string]any{}
	}
	vars["starter"] = starter
	now := e.Now().UTC()
	in := store.Instance{ID: heain.NewID(), Def: d.ID, Version: n, Status: "running", Step: d.First, Vars: vars, Starter: starter,
		Created: now, Updated: now, Trace: heain.TraceID(ctx)}
	if in.Trace == "" {
		in.Trace = heain.NewID()
	}
	in.History = append(in.History, store.Event{At: now, Step: "", What: "started", Who: starter})
	if err := e.Store.PutInstance(ctx, in); err != nil {
		return in, err
	}
	e.audit(heain.WithTrace(ctx, in.Trace, ""), "workflow.run", "started", map[string]any{"workflow": d.ID, "version": n, "instance": in.ID, "by": starter})
	e.wake()
	return in, nil
}

func (e *Engine) save(ctx context.Context, in *store.Instance) error {
	in.Updated = e.Now().UTC()
	return e.Store.PutInstance(ctx, *in)
}

func (e *Engine) goTo(in *store.Instance, step, what string, d map[string]any) {
	in.History = append(in.History, store.Event{At: e.Now().UTC(), Step: in.Step, What: what, Detail: d})
	in.Step, in.Status, in.Wake, in.Wait, in.Attempts = step, "running", time.Time{}, nil, 0
}

// fail sends the instance to step.Error, or fails it.
func (e *Engine) fail(in *store.Instance, s def.Step, err error) {
	if s.Error != "" {
		e.goTo(in, s.Error, "error", map[string]any{"error": err.Error()})
		return
	}
	in.History = append(in.History, store.Event{At: e.Now().UTC(), Step: in.Step, What: "failed", Detail: map[string]any{"error": err.Error()}})
	in.Status, in.Wake, in.Wait = "failed", time.Time{}, nil
}

// retry schedules another attempt of an automatic step, or gives up.
func (e *Engine) retry(in *store.Instance, s def.Step, err error) {
	in.Attempts++
	if in.Attempts >= e.Cfg.MaxAttempts {
		e.fail(in, s, err)
		return
	}
	in.Status, in.Wake = "waiting", e.Now().Add(time.Duration(in.Attempts*in.Attempts)*5*time.Second)
	in.History = append(in.History, store.Event{At: e.Now().UTC(), Step: in.Step, What: "retry", Detail: map[string]any{"error": err.Error(), "attempt": in.Attempts}})
}

func (e *Engine) next(s def.Step, outcome string) string {
	if to := s.On[outcome]; to != "" {
		return to
	}
	return s.Next
}

// Advance moves one instance as far as it can go now.
func (e *Engine) Advance(ctx context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	in, err := e.Store.Instance(ctx, id)
	if err != nil {
		return err
	}
	d, err := e.definition(in.Def, in.Version)
	if err != nil {
		return err
	}
	ctx = heain.WithTrace(ctx, in.Trace, "")
	for i := 0; i < 50 && (in.Status == "running" || (in.Status == "waiting" && !in.Wake.IsZero() && !e.Now().Before(in.Wake))); i++ {
		s, ok := d.Step(in.Step)
		if !ok {
			e.fail(&in, def.Step{}, fmt.Errorf("no step %q", in.Step))
			break
		}
		e.step(ctx, d, &in, s)
	}
	return e.save(ctx, &in)
}

func (e *Engine) step(ctx context.Context, d def.Definition, in *store.Instance, s def.Step) {
	now := e.Now()
	base := map[string]any{"workflow": d.ID, "version": in.Version, "instance": in.ID, "step": s.ID, "type": s.Type}
	entering := in.Wait == nil
	if entering && in.Attempts == 0 && in.Status == "running" && s.Type != "switch" {
		e.audit(ctx, "workflow.run", "step", base)
	}
	switch s.Type {
	case "end":
		in.History = append(in.History, store.Event{At: now.UTC(), Step: s.ID, What: "ended", Detail: map[string]any{"status": s.Status}})
		in.Status, in.Wake, in.Wait = s.Status, time.Time{}, nil
		for _, t := range e.Store.Tasks("open", "claimed") {
			if t.Instance == in.ID {
				t.Status = "cancelled"
				_ = e.Store.PutTask(t)
			}
		}
		e.audit(ctx, "workflow.run", "ended", map[string]any{"workflow": d.ID, "instance": in.ID, "status": s.Status})

	case "switch":
		to := s.Default
		for _, c := range s.Cases {
			if c.Match(in.Vars) {
				to = c.Goto
				break
			}
		}
		e.goTo(in, to, "chose", map[string]any{"to": to})

	case "timer":
		if entering {
			w, _ := def.ParseDuration(s.Wait)
			in.Status, in.Wake, in.Wait = "waiting", now.Add(w), map[string]any{"timer": true}
			return
		}
		e.goTo(in, s.Next, "timer", nil)

	case "task":
		e.task(ctx, d, in, s, entering)

	case "p5":
		if entering {
			r, err := e.Plat.Propose(ctx, heain.Proposal{Type: s.ActionType, Category: heain.CategoryAllowlist,
				Data: map[string]any{"workflow": d.ID, "version": in.Version, "instance": in.ID, "step": s.ID}})
			if err != nil {
				e.retry(in, s, err)
				return
			}
			in.Wait = map[string]any{"action_id": r.ActionID}
			e.p5Result(in, s, r)
			return
		}
		id, _ := in.Wait["action_id"].(string)
		r, err := e.Plat.PolicyStatus(ctx, id)
		if err != nil {
			in.Wake = now.Add(e.Cfg.PollEvery)
			return
		}
		e.p5Result(in, s, r)

	case "app":
		var out struct {
			Outcome string         `json:"outcome"`
			Vars    map[string]any `json:"vars"`
		}
		_, err := e.Plat.Call(ctx, heain.CallSpec{App: s.App, Capability: s.Capability, Method: http.MethodPost, Path: s.Path,
			Body: map[string]any{"workflow": d.ID, "version": in.Version, "instance": in.ID, "step": s.ID, "vars": in.Vars}, Out: &out,
			Timeout: 60 * time.Second})
		if err != nil {
			var ce *heain.CallError
			if errors.As(err, &ce) && ce.Status >= 400 && ce.Status < 500 {
				e.fail(in, s, err) // the app refused: retrying will not help
				return
			}
			e.retry(in, s, err)
			return
		}
		in.Vars[s.ID] = map[string]any{"outcome": out.Outcome, "vars": out.Vars}
		e.goTo(in, e.next(s, out.Outcome), "called", map[string]any{"app": s.App, "outcome": out.Outcome})

	case "job":
		e.job(ctx, in, s, entering)

	case "webhook":
		if err := e.webhook(ctx, d, in, s); err != nil {
			e.retry(in, s, err)
			return
		}
		e.goTo(in, s.Next, "webhook", nil)

	case "notify":
		to := e.targets(in, s.To)
		title := s.Title
		if title == "" {
			title = d.Title + ": " + s.Kind
		}
		var out map[string]any
		_, err := e.Plat.Call(ctx, heain.CallSpec{App: e.Cfg.NotifyApp, Capability: "notify.send", Method: http.MethodPost, Path: "/v1/messages",
			Body: map[string]any{"to": to, "kind": s.Kind, "title": trim(title, 120), "ref": in.ID, "severity": sevOr(s.Severity)}, Out: &out})
		if err != nil && in.Attempts+1 < e.Cfg.MaxAttempts {
			e.retry(in, s, err)
			return
		}
		what := "notified"
		if err != nil {
			what = "notify_failed" // a message never blocks the process
		}
		e.goTo(in, s.Next, what, map[string]any{"to": to})
	}
}

func sevOr(s string) string {
	if s == "" {
		return "info"
	}
	return s
}

func trim(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func (e *Engine) p5Result(in *store.Instance, s def.Step, r heain.PolicyResult) {
	switch {
	case r.Allowed():
		in.Vars[s.ID] = map[string]any{"result": "approved", "action_id": r.ActionID}
		e.goTo(in, s.On["approved"], "approved", map[string]any{"action_id": r.ActionID})
	case r.Result == heain.ResultDenied:
		in.Vars[s.ID] = map[string]any{"result": "denied", "action_id": r.ActionID}
		e.goTo(in, s.On["denied"], "denied", map[string]any{"action_id": r.ActionID})
	default:
		in.Status, in.Wake = "waiting", e.Now().Add(e.Cfg.PollEvery)
	}
}

// targets turns "var:<key>" and "starter" into heain-notify targets.
func (e *Engine) targets(in *store.Instance, to []string) []string {
	var out []string
	for _, t := range to {
		switch {
		case t == "starter" || t == "var:starter":
			out = append(out, "gateway_user:"+in.Starter)
		case strings.HasPrefix(t, "var:"):
			if v, ok := def.Lookup(in.Vars, strings.TrimPrefix(t, "var:")); ok {
				out = append(out, "gateway_user:"+fmt.Sprint(v))
			}
		default:
			out = append(out, t)
		}
	}
	return out
}

func (e *Engine) task(ctx context.Context, d def.Definition, in *store.Instance, s def.Step, entering bool) {
	now := e.Now()
	if entering {
		t := store.Task{ID: heain.NewID(), Instance: in.ID, Def: d.ID, Step: s.ID, Title: s.Title, Outcomes: s.Outcomes, Fields: s.Fields,
			Status: "open", Created: now.UTC()}
		if t.Title == "" {
			t.Title = d.Title + ": " + s.ID
		}
		switch {
		case s.Assign.Role != "":
			t.Role = s.Assign.Role
		case s.Assign.User != "":
			t.User = s.Assign.User
		default:
			if v, ok := def.Lookup(in.Vars, s.Assign.Var); ok {
				t.User = fmt.Sprint(v)
			}
		}
		in.Status, in.Wait = "waiting", map[string]any{"task": t.ID}
		if s.Deadline != "" {
			w, _ := def.ParseDuration(s.Deadline)
			t.Deadline, in.Wake = now.Add(w).UTC(), now.Add(w)
		}
		_ = e.Store.PutTask(t)
		e.tellAboutTask(ctx, in, s, t, "task")
		return
	}
	// woken: the deadline passed (completion is done by Complete)
	id, _ := in.Wait["task"].(string)
	t, err := e.Store.Task(id)
	if err != nil || t.Status == "done" || t.Status == "cancelled" {
		in.Wake = time.Time{}
		return
	}
	t.Overdue = true
	if s.OnDeadline != "" {
		t.Status = "cancelled"
		_ = e.Store.PutTask(t)
		e.goTo(in, s.OnDeadline, "deadline", map[string]any{"task": t.ID})
		return
	}
	_ = e.Store.PutTask(t)
	in.History = append(in.History, store.Event{At: now.UTC(), Step: s.ID, What: "deadline", Detail: map[string]any{"task": t.ID}})
	in.Wake = time.Time{}
	e.tellAboutTask(ctx, in, s, t, "task.overdue")
}

func (e *Engine) tellAboutTask(ctx context.Context, in *store.Instance, s def.Step, t store.Task, kind string) {
	to := e.targets(in, s.Notify)
	if t.User != "" && len(s.Notify) == 0 {
		to = []string{"gateway_user:" + t.User}
	}
	if len(to) == 0 {
		return
	}
	sev := "info"
	if kind == "task.overdue" {
		sev = "warning"
	}
	var out map[string]any
	if _, err := e.Plat.Call(ctx, heain.CallSpec{App: e.Cfg.NotifyApp, Capability: "notify.send", Method: http.MethodPost, Path: "/v1/messages",
		Body: map[string]any{"to": to, "kind": "workflow." + kind, "title": trim(map[string]string{"task": "Task: ", "task.overdue": "Overdue: "}[kind]+t.Title, 120),
			"ref": t.ID, "severity": sev}, Out: &out}); err != nil {
		e.Logf("heain-workflow: telling %v about task %s: %v", to, t.ID, err)
	}
}

func (e *Engine) job(ctx context.Context, in *store.Instance, s def.Step, entering bool) {
	if entering || in.Wait["ticket"] == nil {
		var payload []byte
		if s.Payload != "" {
			if v, ok := def.Lookup(in.Vars, s.Payload); ok {
				payload, _ = json.Marshal(v)
			}
		}
		if payload == nil {
			payload, _ = json.Marshal(map[string]any{"instance": in.ID, "step": s.ID})
		}
		tk, err := e.Plat.Submit(ctx, heain.JobRequest{Capability: s.Capability, Payload: payload, IdempotencyKey: in.ID + "/" + s.ID})
		if err != nil {
			e.retry(in, s, err)
			return
		}
		in.Status, in.Wait, in.Wake = "waiting", map[string]any{"ticket": tk.TicketID}, e.Now().Add(e.Cfg.PollEvery)
		return
	}
	tk, _ := in.Wait["ticket"].(string)
	st, err := e.Plat.Job(ctx, tk)
	if err != nil || !st.Done() {
		in.Wake = e.Now().Add(e.Cfg.PollEvery)
		return
	}
	if st.State != heain.JobCompleted && st.State != heain.JobDelivered {
		in.Vars[s.ID] = map[string]any{"ticket": tk, "state": st.State}
		e.fail(in, s, fmt.Errorf("job %s ended %s", tk, st.State))
		return
	}
	var out any
	if json.Unmarshal(st.Output, &out) != nil {
		out = base64.StdEncoding.EncodeToString(st.Output)
	}
	in.Vars[s.ID] = map[string]any{"ticket": tk, "state": st.State, "output": out}
	_ = e.Plat.ConfirmRetrieval(ctx, tk)
	e.goTo(in, s.Next, "job_done", map[string]any{"ticket": tk})
}

func (e *Engine) webhook(ctx context.Context, d def.Definition, in *store.Instance, s def.Step) error {
	body, _ := json.Marshal(map[string]any{"workflow": d.ID, "version": in.Version, "instance": in.ID, "step": s.ID, "vars": in.Vars})
	h := sha256.Sum256(body)
	sig, err := e.Plat.SignDigest(h[:])
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Heain-Signature", base64.StdEncoding.EncodeToString(sig))
	req.Header.Set("X-Heain-Cert", base64.StdEncoding.EncodeToString(e.Plat.CertDER()))
	req.Header.Set("X-Heain-Workflow-Instance", in.ID)
	resp, err := e.Cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %d", resp.StatusCode)
	}
	return nil
}

// ---- tasks (people) ----

// ErrForbidden: the person may not do this.
var ErrForbidden = errors.New("forbidden")

// CanSee reports whether a person (id, roles) may see or take t.
func CanSee(t store.Task, user string, roles []string) bool {
	if t.User != "" {
		return t.User == user
	}
	for _, r := range roles {
		if r == t.Role {
			return t.Status == "open" || t.ClaimedBy == user
		}
	}
	return false
}

// Claim takes a role task for a person.
func (e *Engine) Claim(user string, roles []string, id string) (store.Task, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, err := e.Store.Task(id)
	if err != nil {
		return t, err
	}
	if !CanSee(t, user, roles) || t.Status != "open" {
		return t, ErrForbidden
	}
	t.Status, t.ClaimedBy = "claimed", user
	return t, e.Store.PutTask(t)
}

// Complete finishes a task with an outcome and the person's fields.
func (e *Engine) Complete(ctx context.Context, user string, roles []string, id, outcome string, data map[string]any) (store.Task, error) {
	e.mu.Lock()
	t, err := e.Store.Task(id)
	if err != nil {
		e.mu.Unlock()
		return t, err
	}
	if !CanSee(t, user, roles) || (t.Status != "open" && t.Status != "claimed") || (t.Status == "claimed" && t.ClaimedBy != user) {
		e.mu.Unlock()
		return t, ErrForbidden
	}
	ok := false
	for _, o := range t.Outcomes {
		if o == outcome {
			ok = true
		}
	}
	if !ok {
		e.mu.Unlock()
		return t, fmt.Errorf("outcome must be one of %v", t.Outcomes)
	}
	fields := map[string]any{}
	allowed := map[string]bool{}
	for _, f := range t.Fields {
		allowed[f] = true
	}
	for k, v := range data {
		if !allowed[k] {
			e.mu.Unlock()
			return t, fmt.Errorf("field %q is not part of this task (fields: %v)", k, t.Fields)
		}
		fields[k] = v
	}
	in, err := e.Store.Instance(ctx, t.Instance)
	if err != nil {
		e.mu.Unlock()
		return t, err
	}
	d, err := e.definition(in.Def, in.Version)
	if err != nil {
		e.mu.Unlock()
		return t, err
	}
	s, _ := d.Step(t.Step)
	t.Status, t.Outcome, t.DoneBy, t.Done = "done", outcome, user, e.Now().UTC()
	if err := e.Store.PutTask(t); err != nil {
		e.mu.Unlock()
		return t, err
	}
	if in.Step == t.Step && (in.Status == "waiting" || in.Status == "running") {
		in.Vars[s.ID] = map[string]any{"outcome": outcome, "by": user, "fields": fields}
		in.History = append(in.History, store.Event{At: e.Now().UTC(), Step: s.ID, What: "outcome:" + outcome, Who: user})
		in.Step, in.Status, in.Wake, in.Wait, in.Attempts = e.next(s, outcome), "running", time.Time{}, nil, 0
		if err := e.save(ctx, &in); err != nil {
			e.mu.Unlock()
			return t, err
		}
	}
	e.mu.Unlock()
	e.wake()
	return t, nil
}

// Inbox lists the tasks a person may see now.
func (e *Engine) Inbox(user string, roles []string) []store.Task {
	out := []store.Task{}
	for _, t := range e.Store.Tasks("open", "claimed") {
		if CanSee(t, user, roles) {
			out = append(out, t)
		}
	}
	return out
}

// Cancel stops an instance.
func (e *Engine) Cancel(ctx context.Context, id, by string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	in, err := e.Store.Instance(ctx, id)
	if err != nil {
		return err
	}
	if in.Status != "running" && in.Status != "waiting" {
		return fmt.Errorf("instance is %s", in.Status)
	}
	in.History = append(in.History, store.Event{At: e.Now().UTC(), Step: in.Step, What: "cancelled", Who: by})
	in.Status, in.Wake, in.Wait = "cancelled", time.Time{}, nil
	for _, t := range e.Store.Tasks("open", "claimed") {
		if t.Instance == id {
			t.Status = "cancelled"
			_ = e.Store.PutTask(t)
		}
	}
	return e.save(ctx, &in)
}

// ---- the loop ----

// schedules starts instances of active definitions whose schedule is due.
func (e *Engine) schedules(ctx context.Context) {
	now := e.Now().In(e.Cfg.Location).Truncate(time.Minute)
	for _, rec := range e.Store.Defs() {
		if rec.Active == 0 {
			continue
		}
		d, err := e.definition(rec.ID, rec.Active)
		if err != nil || d.Schedule == "" {
			continue
		}
		c, err := def.ParseCron(d.Schedule)
		if err != nil || !c.Matches(now) || !rec.LastScheduled.Before(now) {
			continue
		}
		rec.LastScheduled = now
		e.mu.Lock()
		_ = e.Store.PutDef(rec)
		e.mu.Unlock()
		vars := map[string]any{}
		for k, v := range d.ScheduleVars {
			vars[k] = v
		}
		if _, err := e.Start(ctx, rec.ID, vars, "schedule"); err != nil {
			e.Logf("heain-workflow: scheduled start of %s: %v", rec.ID, err)
		}
	}
}

// Tick does one round: decisions on definitions, schedules, due instances.
func (e *Engine) Tick(ctx context.Context) {
	e.pollDefinitions(ctx)
	e.schedules(ctx)
	for _, id := range e.Store.Due(e.Now()) {
		if err := e.Advance(ctx, id); err != nil {
			e.Logf("heain-workflow: instance %s: %v", id, err)
		}
	}
}

// Run ticks every second (and when woken) until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		}
		e.Tick(ctx)
	}
}

// Summary is an instance as a list shows it.
type Summary struct {
	ID      string    `json:"id"`
	Def     string    `json:"workflow"`
	Version int       `json:"version"`
	Status  string    `json:"status"`
	Step    string    `json:"step"`
	Starter string    `json:"starter"`
	Created time.Time `json:"created"`
}

// Instances lists summaries the filter accepts.
func (e *Engine) Instances(ctx context.Context, keep func(store.Instance) bool) []Summary {
	out := []Summary{}
	for _, id := range e.Store.InstanceIDs() {
		in, err := e.Store.Instance(ctx, id)
		if err == nil && keep(in) {
			out = append(out, Summary{in.ID, in.Def, in.Version, in.Status, in.Step, in.Starter, in.Created})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}
