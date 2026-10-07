// Package def is a workflow definition (author decision 2026-10-07): a state
// machine in YAML or JSON. Each step has a type:
//
//	task     a person does it (a role, a person, or a person named in the
//	         data); outcomes lead to the next steps; deadline + on_deadline
//	p5       core's Approver decides (approved / denied)
//	app      call an app that opts in with a capability named *.step
//	job      submit a core job (P1-P4) to a *.step (or job.orchestrate) capability and wait
//	webhook  POST to an external system, signed with the app key
//	notify   send a message through heain-notify (references only)
//	timer    wait (a duration)
//	switch   choose the next step from the data
//	end      the instance ends (completed, rejected, ...)
package def

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Definition is one workflow.
type Definition struct {
	ID       string `json:"id" yaml:"id"`
	Title    string `json:"title,omitempty" yaml:"title,omitempty"`
	Start    Start  `json:"start" yaml:"start"`
	First    string `json:"first" yaml:"first"` // the first step
	Steps    []Step `json:"steps" yaml:"steps"`
	Schedule string `json:"schedule,omitempty" yaml:"schedule,omitempty"` // cron: start an instance on this schedule
	// ScheduleVars are the data of a scheduled instance.
	ScheduleVars map[string]any `json:"schedule_vars,omitempty" yaml:"schedule_vars,omitempty"`
}

// Start says who may start an instance.
type Start struct {
	Roles []string `json:"roles,omitempty" yaml:"roles,omitempty"` // people with one of these roles (through heain-gateway)
	Apps  []string `json:"apps,omitempty" yaml:"apps,omitempty"`   // apps that may start it
}

// Step is one state.
type Step struct {
	ID    string            `json:"id" yaml:"id"`
	Type  string            `json:"type" yaml:"type"`
	Title string            `json:"title,omitempty" yaml:"title,omitempty"`
	Next  string            `json:"next,omitempty" yaml:"next,omitempty"`   // the step after (single path)
	On    map[string]string `json:"on,omitempty" yaml:"on,omitempty"`       // outcome -> step
	Error string            `json:"error,omitempty" yaml:"error,omitempty"` // where a failed automatic step goes (else the instance fails)

	// task
	Assign     *Assign  `json:"assign,omitempty" yaml:"assign,omitempty"`
	Outcomes   []string `json:"outcomes,omitempty" yaml:"outcomes,omitempty"`
	Fields     []string `json:"fields,omitempty" yaml:"fields,omitempty"` // data the person may add
	Deadline   string   `json:"deadline,omitempty" yaml:"deadline,omitempty"`
	OnDeadline string   `json:"on_deadline,omitempty" yaml:"on_deadline,omitempty"` // a step; empty: remind and keep waiting
	Notify     []string `json:"notify,omitempty" yaml:"notify,omitempty"`           // heain-notify targets told about the task

	// p5
	ActionType string `json:"action_type,omitempty" yaml:"action_type,omitempty"`

	// app / job
	App        string `json:"app,omitempty" yaml:"app,omitempty"`
	Capability string `json:"capability,omitempty" yaml:"capability,omitempty"`
	Path       string `json:"path,omitempty" yaml:"path,omitempty"`
	Payload    string `json:"payload,omitempty" yaml:"payload,omitempty"` // job: the data key whose value is the payload (JSON)

	// webhook
	URL string `json:"url,omitempty" yaml:"url,omitempty"`

	// notify
	To       []string `json:"to,omitempty" yaml:"to,omitempty"`
	Kind     string   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Severity string   `json:"severity,omitempty" yaml:"severity,omitempty"`

	// timer
	Wait string `json:"wait,omitempty" yaml:"wait,omitempty"`

	// switch
	Cases   []Case `json:"cases,omitempty" yaml:"cases,omitempty"`
	Default string `json:"default,omitempty" yaml:"default,omitempty"`

	// end
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
}

// Assign names who does a task: one of role, user, or var (a data key
// holding an account id; "starter" is the person who started it).
type Assign struct {
	Role string `json:"role,omitempty" yaml:"role,omitempty"`
	User string `json:"user,omitempty" yaml:"user,omitempty"`
	Var  string `json:"var,omitempty" yaml:"var,omitempty"`
}

// Case is one switch branch: data[Var] <op> Value -> Goto.
type Case struct {
	Var   string `json:"var" yaml:"var"`
	Op    string `json:"op" yaml:"op"` // == != > >= < <= in
	Value any    `json:"value" yaml:"value"`
	Goto  string `json:"goto" yaml:"goto"`
}

var (
	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	varRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,62}$`)
	appRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	ruleOps = map[string]bool{"==": true, "!=": true, ">": true, ">=": true, "<": true, "<=": true, "in": true}
)

// Parse reads YAML or JSON and validates it.
func Parse(b []byte) (Definition, error) {
	var d Definition
	s := strings.TrimSpace(string(b))
	var err error
	if strings.HasPrefix(s, "{") {
		dec := json.NewDecoder(strings.NewReader(s))
		dec.DisallowUnknownFields()
		err = dec.Decode(&d)
	} else {
		dec := yaml.NewDecoder(strings.NewReader(s))
		dec.KnownFields(true)
		err = dec.Decode(&d)
	}
	if err != nil {
		return d, fmt.Errorf("definition: %w", err)
	}
	return d, d.Validate()
}

// Step finds a step.
func (d Definition) Step(id string) (Step, bool) {
	for _, s := range d.Steps {
		if s.ID == id {
			return s, true
		}
	}
	return Step{}, false
}

// AllowedCapability: automatic steps call only capabilities apps opened to
// workflows (*.step), or heain-job's orchestration for jobs.
func AllowedCapability(typ, c string) bool {
	if strings.HasSuffix(c, ".step") && len(c) > 5 {
		return true
	}
	return typ == "job" && c == "job.orchestrate"
}

// Validate checks the whole definition.
func (d Definition) Validate() error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if !idRe.MatchString(d.ID) {
		bad("id must match %s", idRe)
	}
	if len(d.Steps) == 0 || len(d.Steps) > 200 {
		bad("1-200 steps")
	}
	for _, r := range d.Start.Roles {
		if !nameRe.MatchString(r) {
			bad("start.roles: %q", r)
		}
	}
	for _, a := range d.Start.Apps {
		if !appRe.MatchString(a) {
			bad("start.apps: %q", a)
		}
	}
	if d.Schedule != "" {
		if _, err := ParseCron(d.Schedule); err != nil {
			bad("schedule: %v", err)
		}
	}
	ids := map[string]bool{}
	for _, s := range d.Steps {
		if !idRe.MatchString(s.ID) || ids[s.ID] {
			bad("step id %q is invalid or repeated", s.ID)
		}
		ids[s.ID] = true
	}
	if !ids[d.First] {
		bad("first: no step %q", d.First)
	}
	ref := func(s Step, what, to string) {
		if to != "" && !ids[to] {
			bad("step %s: %s leads to unknown step %q", s.ID, what, to)
		}
	}
	dur := func(s Step, what, v string) {
		if v == "" {
			return
		}
		if x, err := ParseDuration(v); err != nil || x <= 0 {
			bad("step %s: %s %q is not a duration (e.g. 30m, 48h, 7d)", s.ID, what, v)
		}
	}
	ends := 0
	for _, s := range d.Steps {
		ref(s, "next", s.Next)
		ref(s, "error", s.Error)
		for o, to := range s.On {
			ref(s, "on."+o, to)
		}
		switch s.Type {
		case "task":
			if s.Assign == nil || countAssign(s.Assign) != 1 {
				bad("step %s: assign exactly one of role, user, var", s.ID)
			}
			if len(s.Outcomes) == 0 {
				bad("step %s: a task needs outcomes", s.ID)
			}
			for _, o := range s.Outcomes {
				if !nameRe.MatchString(o) {
					bad("step %s: outcome %q", s.ID, o)
				}
				if s.On[o] == "" && s.Next == "" {
					bad("step %s: outcome %q leads nowhere (on.%s or next)", s.ID, o, o)
				}
			}
			for _, f := range s.Fields {
				if !varRe.MatchString(f) {
					bad("step %s: field %q", s.ID, f)
				}
			}
			dur(s, "deadline", s.Deadline)
			ref(s, "on_deadline", s.OnDeadline)
		case "p5":
			if !nameRe.MatchString(s.ActionType) {
				bad("step %s: action_type is required ([a-z0-9._-])", s.ID)
			}
			if s.On["approved"] == "" || s.On["denied"] == "" {
				bad("step %s: on.approved and on.denied are required", s.ID)
			}
		case "app", "job":
			if !AllowedCapability(s.Type, s.Capability) {
				bad("step %s: capability %q is not open to workflows (it must end in .step)", s.ID, s.Capability)
			}
			if s.Type == "app" && (!appRe.MatchString(s.App) || !strings.HasPrefix(s.Path, "/")) {
				bad("step %s: app and path are required", s.ID)
			}
			if s.Next == "" && len(s.On) == 0 {
				bad("step %s: next is required", s.ID)
			}
		case "webhook":
			u, err := url.Parse(s.URL)
			if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
				bad("step %s: url must be https", s.ID)
			}
			if s.Next == "" {
				bad("step %s: next is required", s.ID)
			}
		case "notify":
			if len(s.To) == 0 || !nameRe.MatchString(s.Kind) || s.Next == "" {
				bad("step %s: to, kind and next are required", s.ID)
			}
		case "timer":
			dur(s, "wait", s.Wait)
			if s.Wait == "" || s.Next == "" {
				bad("step %s: wait and next are required", s.ID)
			}
		case "switch":
			if len(s.Cases) == 0 || s.Default == "" {
				bad("step %s: cases and default are required", s.ID)
			}
			ref(s, "default", s.Default)
			for _, c := range s.Cases {
				if !varRe.MatchString(c.Var) || !ruleOps[c.Op] {
					bad("step %s: case %v", s.ID, c)
				}
				ref(s, "case", c.Goto)
			}
		case "end":
			ends++
			if s.Status == "" {
				bad("step %s: an end needs a status", s.ID)
			}
		default:
			bad("step %s: unknown type %q", s.ID, s.Type)
		}
	}
	if ends == 0 {
		bad("at least one end step")
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func countAssign(a *Assign) int {
	n := 0
	for _, v := range []string{a.Role, a.User, a.Var} {
		if v != "" {
			n++
		}
	}
	return n
}

// ParseDuration takes Go durations and days ("7d").
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Match evaluates a switch case against the data.
func (c Case) Match(vars map[string]any) bool {
	v, ok := Lookup(vars, c.Var)
	if !ok {
		return c.Op == "!="
	}
	if c.Op == "in" {
		l, _ := c.Value.([]any)
		for _, x := range l {
			if fmt.Sprint(x) == fmt.Sprint(v) {
				return true
			}
		}
		return false
	}
	a, aok := num(v)
	b, bok := num(c.Value)
	if aok && bok {
		switch c.Op {
		case "==":
			return a == b
		case "!=":
			return a != b
		case ">":
			return a > b
		case ">=":
			return a >= b
		case "<":
			return a < b
		case "<=":
			return a <= b
		}
	}
	switch c.Op {
	case "==":
		return fmt.Sprint(v) == fmt.Sprint(c.Value)
	case "!=":
		return fmt.Sprint(v) != fmt.Sprint(c.Value)
	}
	return false
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

// Lookup reads a dotted key ("review.comment") from the data.
func Lookup(vars map[string]any, key string) (any, bool) {
	var cur any = vars
	for _, p := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}
