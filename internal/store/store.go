// Package store keeps heain-workflow's state in BoltDB, sealed under data
// keys held by heain-core's KMS: definitions and their versions, tasks and
// schedules under the app's inside key; each instance (its data and
// history) under its own key, so removing an instance is a crypto-shred.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	bolt "go.etcd.io/bbolt"
)

var (
	bDefs      = []byte("definitions")
	bInstances = []byte("instances")
	bTasks     = []byte("tasks")
	bMeta      = []byte("meta")
)

// ErrNotFound: no such record.
var ErrNotFound = errors.New("not found")

// Keys gives per-instance keys (core's KMS).
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Store is the sealed state.
type Store struct {
	db     *bolt.DB
	inside *heain.Sealer
	ixKey  []byte
	keys   Keys
}

// Open opens (creating) the store.
func Open(path string, inside []byte, keys Keys) (*Store, error) {
	s, err := heain.NewSealer(inside)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bDefs, bInstances, bTasks, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, inside)
	m.Write([]byte("heain-workflow/index"))
	return &Store{db: db, inside: s, ixKey: m.Sum(nil), keys: keys}, nil
}

// Close closes the store.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ix(kind, id string) string {
	m := hmac.New(sha256.New, s.ixKey)
	m.Write([]byte(kind + "\x00" + id))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) put(b []byte, kind, id string, v any) error {
	k := s.ix(kind, id)
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Put([]byte(k), s.inside.Seal(raw, []byte(kind+"/"+k))) })
}

func (s *Store) get(b []byte, kind, id string, v any) error {
	k := s.ix(kind, id)
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if x := tx.Bucket(b).Get([]byte(k)); x != nil {
			sealed = append([]byte(nil), x...)
		}
		return nil
	})
	if sealed == nil {
		return ErrNotFound
	}
	raw, err := s.inside.Open(sealed, []byte(kind+"/"+k))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Store) del(b []byte, kind, id string) error {
	k := s.ix(kind, id)
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Delete([]byte(k)) })
}

func (s *Store) each(b []byte, kind string, f func(raw []byte)) {
	type kv struct{ k, v []byte }
	var all []kv
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(b).ForEach(func(k, v []byte) error {
			all = append(all, kv{append([]byte(nil), k...), append([]byte(nil), v...)})
			return nil
		})
	})
	for _, x := range all {
		if raw, err := s.inside.Open(x.v, []byte(kind+"/"+string(x.k))); err == nil {
			f(raw)
		}
	}
}

// ---- definitions ----

// Version is one submitted version of a definition.
type Version struct {
	N         int       `json:"n"`
	Source    string    `json:"source"` // the YAML/JSON as submitted
	SHA256    string    `json:"sha256"`
	By        string    `json:"by"`
	At        time.Time `json:"at"`
	State     string    `json:"state"` // proposed | active | retired | denied
	ActionID  string    `json:"action_id,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitempty"`
}

// DefRecord is a definition with its versions.
type DefRecord struct {
	ID       string    `json:"id"`
	Active   int       `json:"active"` // 0 = none yet
	Versions []Version `json:"versions"`
	// LastScheduled is the last minute a scheduled instance was started.
	LastScheduled time.Time `json:"last_scheduled,omitempty"`
}

// PutDef stores a definition record.
func (s *Store) PutDef(d DefRecord) error { return s.put(bDefs, "def", d.ID, d) }

// Def reads one.
func (s *Store) Def(id string) (DefRecord, error) {
	var d DefRecord
	return d, s.get(bDefs, "def", id, &d)
}

// Defs lists them.
func (s *Store) Defs() []DefRecord {
	out := []DefRecord{}
	s.each(bDefs, "def", func(raw []byte) {
		var d DefRecord
		if json.Unmarshal(raw, &d) == nil {
			out = append(out, d)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- instances ----

// Event is one line of an instance's history.
type Event struct {
	At     time.Time      `json:"at"`
	Step   string         `json:"step"`
	What   string         `json:"what"` // entered | completed | outcome:<o> | deadline | error | ...
	Who    string         `json:"who,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

// Instance is one run of a definition version.
type Instance struct {
	ID       string         `json:"id"`
	Def      string         `json:"def"`
	Version  int            `json:"version"`
	Status   string         `json:"status"` // running | waiting | <end status> | failed | cancelled
	Step     string         `json:"step"`
	Vars     map[string]any `json:"vars"`
	Starter  string         `json:"starter"`            // the person (account id) or app that started it
	Wake     time.Time      `json:"wake,omitempty"`     // timer, retry or poll
	Wait     map[string]any `json:"wait,omitempty"`     // what the current step waits on (p5 action, job ticket, task id)
	Attempts int            `json:"attempts,omitempty"` // of the current automatic step
	History  []Event        `json:"history"`
	Created  time.Time      `json:"created"`
	Updated  time.Time      `json:"updated"`
	Trace    string         `json:"trace,omitempty"`
}

type instEnv struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Sealed []byte `json:"sealed"`
	// the engine scans these without opening the instance
	Status string    `json:"status"`
	Wake   time.Time `json:"wake,omitempty"`
}

func (s *Store) instKey(id string) string { return "inst-" + s.ix("inst", id)[:24] }

// PutInstance stores an instance under its own key.
func (s *Store) PutInstance(ctx context.Context, in Instance) error {
	kn := s.instKey(in.ID)
	ks, err := s.keys.Sealer(ctx, kn)
	if err != nil {
		return fmt.Errorf("instance key: %w", err)
	}
	raw, _ := json.Marshal(in)
	return s.put(bInstances, "inst", in.ID, instEnv{ID: in.ID, Key: kn, Sealed: ks.Seal(raw, []byte("inst/"+in.ID)), Status: in.Status, Wake: in.Wake})
}

// Instance reads one.
func (s *Store) Instance(ctx context.Context, id string) (Instance, error) {
	var env instEnv
	if err := s.get(bInstances, "inst", id, &env); err != nil {
		return Instance{}, err
	}
	ks, err := s.keys.Sealer(ctx, env.Key)
	if err != nil {
		return Instance{}, fmt.Errorf("instance key: %w", err)
	}
	raw, err := ks.Open(env.Sealed, []byte("inst/"+id))
	if err != nil {
		return Instance{}, err
	}
	var in Instance
	return in, json.Unmarshal(raw, &in)
}

// Due lists the instances the engine should look at now: running ones, and
// waiting ones whose wake time has come.
func (s *Store) Due(now time.Time) []string {
	var ids []string
	s.each(bInstances, "inst", func(raw []byte) {
		var env instEnv
		if json.Unmarshal(raw, &env) == nil && (env.Status == "running" || (env.Status == "waiting" && !env.Wake.IsZero() && !now.Before(env.Wake))) {
			ids = append(ids, env.ID)
		}
	})
	sort.Strings(ids)
	return ids
}

// InstanceIDs lists every instance id.
func (s *Store) InstanceIDs() []string {
	var ids []string
	s.each(bInstances, "inst", func(raw []byte) {
		var env instEnv
		if json.Unmarshal(raw, &env) == nil {
			ids = append(ids, env.ID)
		}
	})
	sort.Strings(ids)
	return ids
}

// DeleteInstance destroys the instance's key, then the record.
func (s *Store) DeleteInstance(ctx context.Context, id string) error {
	if err := s.keys.Destroy(ctx, s.instKey(id)); err != nil {
		return fmt.Errorf("destroying the instance key: %w", err)
	}
	return s.del(bInstances, "inst", id)
}

// ---- tasks ----

// Task is a person's piece of an instance.
type Task struct {
	ID        string    `json:"id"`
	Instance  string    `json:"instance"`
	Def       string    `json:"def"`
	Step      string    `json:"step"`
	Title     string    `json:"title"`
	Role      string    `json:"role,omitempty"`
	User      string    `json:"user,omitempty"`
	Outcomes  []string  `json:"outcomes"`
	Fields    []string  `json:"fields,omitempty"`
	Status    string    `json:"status"` // open | claimed | done | cancelled
	ClaimedBy string    `json:"claimed_by,omitempty"`
	Deadline  time.Time `json:"deadline,omitempty"`
	Overdue   bool      `json:"overdue,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
	DoneBy    string    `json:"done_by,omitempty"`
	Created   time.Time `json:"created"`
	Done      time.Time `json:"done,omitempty"`
}

// PutTask stores a task.
func (s *Store) PutTask(t Task) error { return s.put(bTasks, "task", t.ID, t) }

// Task reads one.
func (s *Store) Task(id string) (Task, error) {
	var t Task
	return t, s.get(bTasks, "task", id, &t)
}

// Tasks lists tasks (all when status is "").
func (s *Store) Tasks(status ...string) []Task {
	want := map[string]bool{}
	for _, x := range status {
		want[x] = true
	}
	out := []Task{}
	s.each(bTasks, "task", func(raw []byte) {
		var t Task
		if json.Unmarshal(raw, &t) == nil && (len(want) == 0 || want[t.Status]) {
			out = append(out, t)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}
