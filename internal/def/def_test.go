package def

import (
	"strings"
	"testing"
	"time"
)

const purchase = `
id: purchase
title: Purchase request
start: {roles: [staff]}
first: review
steps:
  - {id: review, type: task, assign: {role: manager}, outcomes: [approve, reject], fields: [comment], deadline: 2d, on: {approve: amount, reject: rejected}, notify: ["group:managers"]}
  - {id: amount, type: switch, cases: [{var: amount, op: ">", value: 100000, goto: finance}], default: issue}
  - {id: finance, type: p5, action_type: purchase.approve, on: {approved: issue, denied: rejected}}
  - {id: issue, type: app, app: docs, capability: docs.issue.step, path: /v1/issue, next: tell, error: rejected}
  - {id: tell, type: notify, to: ["var:starter"], kind: purchase.issued, next: done}
  - {id: done, type: end, status: completed}
  - {id: rejected, type: end, status: rejected}
`

func TestParse(t *testing.T) {
	d, err := Parse([]byte(purchase))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := d.Step("finance"); !ok || s.On["approved"] != "issue" {
		t.Fatal("step")
	}
	for name, bad := range map[string]string{
		"unknown next":        strings.Replace(purchase, "next: done", "next: nowhere", 1),
		"no end":              strings.Replace(strings.Replace(purchase, "type: end, status: completed", "type: timer, wait: 1h, next: rejected", 1), "type: end, status: rejected", "type: timer, wait: 1h, next: done", 1),
		"capability not open": strings.Replace(purchase, "docs.issue.step", "docs.issue", 1),
		"two assignees":       strings.Replace(purchase, "{role: manager}", "{role: manager, user: x}", 1),
		"bad deadline":        strings.Replace(purchase, "deadline: 2d", "deadline: soon", 1),
		"unknown field":       strings.Replace(purchase, "title: Purchase request", "titel: x", 1),
		"bad cron":            purchase + "schedule: \"61 * * * *\"\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !AllowedCapability("job", "job.orchestrate") || AllowedCapability("app", "job.orchestrate") {
		t.Fatal("job.orchestrate only for jobs")
	}
}

func TestCases(t *testing.T) {
	v := map[string]any{"amount": 150000.0, "review": map[string]any{"outcome": "approve"}, "dept": "it"}
	for c, want := range map[Case]bool{
		{Var: "amount", Op: ">", Value: 100000}:             true,
		{Var: "amount", Op: "<=", Value: "100000"}:          false,
		{Var: "review.outcome", Op: "==", Value: "approve"}: true,
		{Var: "missing", Op: "!=", Value: "x"}:              true,
		{Var: "missing", Op: "==", Value: "x"}:              false,
	} {
		if c.Match(v) != want {
			t.Errorf("%+v", c)
		}
	}
	if !(Case{Var: "dept", Op: "in", Value: []any{"hr", "it"}}).Match(v) {
		t.Fatal("in")
	}
}

func TestCron(t *testing.T) {
	c, err := ParseCron("30 9 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}
	fri := time.Date(2026, 10, 9, 9, 30, 0, 0, time.UTC) // a Friday
	if !c.Matches(fri) || c.Matches(fri.Add(time.Minute)) || c.Matches(fri.AddDate(0, 0, 1)) {
		t.Fatal("weekday 09:30")
	}
	if n := c.Next(fri); !n.Equal(time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC)) {
		t.Fatalf("next after Friday: %v", n)
	}
	e, _ := ParseCron("*/15 * * * *")
	if !e.Matches(time.Date(2026, 1, 1, 3, 45, 0, 0, time.UTC)) || e.Matches(time.Date(2026, 1, 1, 3, 44, 0, 0, time.UTC)) {
		t.Fatal("steps")
	}
	s7, _ := ParseCron("0 0 * * 7")
	if !s7.Matches(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("sunday as 7")
	}
	for _, b := range []string{"* * * *", "60 * * * *", "* 24 * * *", "5-1 * * * *", "*/0 * * * *"} {
		if _, err := ParseCron(b); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	if d, _ := ParseDuration("7d"); d != 7*24*time.Hour {
		t.Fatal("days")
	}
}
