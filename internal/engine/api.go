package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-workflow/internal/def"
	"github.com/heainframework/heain-workflow/internal/store"
)

// App-plane API (mTLS, served by heain-sdk); every endpoint is declared
// public, so heain-gateway may expose it to people (through P5):
//
//	PUT  /v1/definitions/{id}            a new version (YAML or JSON body) -> P5 activation   (workflow-admin)
//	GET  /v1/definitions  GET /v1/definitions/{id}                                          (workflow-admin)
//	GET  /v1/workflows                   the active workflows the caller may start
//	POST /v1/workflows/{id}/instances {vars}   start one (start.roles / start.apps)
//	GET  /v1/instances                   mine (a person: started or worked on; an admin: all)
//	GET  /v1/instances/{id}
//	POST /v1/instances/{id}/cancel                                                         (workflow-admin)
//	GET  /v1/tasks                       my inbox (my tasks and my roles' open tasks)
//	POST /v1/tasks/{id}/claim
//	POST /v1/tasks/{id}/complete {outcome, data}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, c, msg string) {
	reply(w, code, map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

func callerApp(r *http.Request) string {
	a, _, _ := strings.Cut(heain.Caller(r.Context()), ".")
	return a
}

func (e *Engine) isAdmin(r *http.Request) bool {
	if u := heain.UserOf(r.Context()); u != nil {
		return u.HasRole(AdminRole)
	}
	for _, a := range e.Cfg.AdminCallers {
		if a == callerApp(r) {
			return true
		}
	}
	return false
}

// who is the person (account id) or the calling app.
func who(r *http.Request) (id string, roles []string, person bool) {
	if u := heain.UserOf(r.Context()); u != nil {
		return u.ID, u.Roles, true
	}
	return heain.Caller(r.Context()), nil, false
}

// Register adds the endpoints to the app's server.
func (e *Engine) Register(srv *heain.Server) error {
	for pat, h := range map[string]http.HandlerFunc{
		"PUT /v1/definitions/{id}":          e.putDefinition,
		"GET /v1/definitions":               e.listDefinitions,
		"GET /v1/definitions/{id}":          e.getDefinition,
		"GET /v1/workflows":                 e.listWorkflows,
		"POST /v1/workflows/{id}/instances": e.startInstance,
		"GET /v1/instances":                 e.listInstances,
		"GET /v1/instances/{id}":            e.getInstance,
		"POST /v1/instances/{id}/cancel":    e.cancelInstance,
		"GET /v1/tasks":                     e.inbox,
		"POST /v1/tasks/{id}/claim":         e.claim,
		"POST /v1/tasks/{id}/complete":      e.complete,
	} {
		if err := srv.HandleFunc(pat, h); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) putDefinition(w http.ResponseWriter, r *http.Request) {
	if !e.isAdmin(r) {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
		return
	}
	src, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "body too large or unreadable")
		return
	}
	// a JSON body {"source": "..."} is accepted too
	var wrap struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(src, &wrap) == nil && wrap.Source != "" {
		src = []byte(wrap.Source)
	}
	if d, err := def.Parse(src); err != nil {
		fail(w, http.StatusBadRequest, "invalid_definition", err.Error())
		return
	} else if d.ID != r.PathValue("id") {
		fail(w, http.StatusBadRequest, "invalid_definition", "the body defines "+d.ID+", the path names "+r.PathValue("id"))
		return
	}
	id, _, _ := who(r)
	v, err := e.SubmitDefinition(r.Context(), src, id)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	reply(w, http.StatusAccepted, map[string]any{"version": v.N, "state": v.State, "action_id": v.ActionID, "sha256": v.SHA256})
}

func (e *Engine) listDefinitions(w http.ResponseWriter, r *http.Request) {
	if !e.isAdmin(r) {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
		return
	}
	type row struct {
		ID       string `json:"id"`
		Active   int    `json:"active"`
		Versions int    `json:"versions"`
		Last     string `json:"last_state"`
	}
	out := []row{}
	for _, d := range e.Store.Defs() {
		out = append(out, row{d.ID, d.Active, len(d.Versions), d.Versions[len(d.Versions)-1].State})
	}
	reply(w, http.StatusOK, map[string]any{"definitions": out})
}

func (e *Engine) getDefinition(w http.ResponseWriter, r *http.Request) {
	if !e.isAdmin(r) {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
		return
	}
	d, err := e.Store.Def(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such workflow")
		return
	}
	reply(w, http.StatusOK, d)
}

func (e *Engine) mayStart(r *http.Request, id string) (bool, error) {
	d, _, err := e.Active(id)
	if err != nil {
		return false, err
	}
	_, roles, person := who(r)
	if person {
		for _, want := range d.Start.Roles {
			for _, have := range roles {
				if want == have {
					return true, nil
				}
			}
		}
		return false, nil
	}
	for _, a := range d.Start.Apps {
		if a == callerApp(r) {
			return true, nil
		}
	}
	return false, nil
}

func (e *Engine) listWorkflows(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Version int    `json:"version"`
	}
	out := []row{}
	for _, rec := range e.Store.Defs() {
		if ok, _ := e.mayStart(r, rec.ID); ok {
			d, n, _ := e.Active(rec.ID)
			out = append(out, row{d.ID, d.Title, n})
		}
	}
	reply(w, http.StatusOK, map[string]any{"workflows": out})
}

func (e *Engine) startInstance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ok, err := e.mayStart(r, id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if !ok {
		fail(w, http.StatusForbidden, "forbidden", "you may not start "+id)
		return
	}
	var q struct {
		Vars map[string]any `json:"vars"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "body: {\"vars\": {...}}")
		return
	}
	starter, _, _ := who(r)
	in, err := e.Start(r.Context(), id, q.Vars, starter)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	reply(w, http.StatusCreated, map[string]any{"instance": in.ID, "workflow": in.Def, "version": in.Version, "status": in.Status})
}

// involved: the person started it or worked on one of its tasks.
func (e *Engine) involved(in store.Instance, user string) bool {
	if in.Starter == user {
		return true
	}
	for _, h := range in.History {
		if h.Who == user {
			return true
		}
	}
	for _, t := range e.Store.Tasks() {
		if t.Instance == in.ID && (t.User == user || t.ClaimedBy == user) {
			return true
		}
	}
	return false
}

func (e *Engine) listInstances(w http.ResponseWriter, r *http.Request) {
	user, _, _ := who(r)
	admin := e.isAdmin(r)
	reply(w, http.StatusOK, map[string]any{"instances": e.Instances(r.Context(), func(in store.Instance) bool {
		return admin || e.involved(in, user)
	})})
}

func (e *Engine) getInstance(w http.ResponseWriter, r *http.Request) {
	in, err := e.Store.Instance(r.Context(), r.PathValue("id"))
	user, roles, _ := who(r)
	if err == nil && !e.isAdmin(r) && !e.involved(in, user) {
		// someone who can see one of its open tasks may see it too
		visible := false
		for _, t := range e.Store.Tasks("open", "claimed") {
			if t.Instance == in.ID && CanSee(t, user, roles) {
				visible = true
			}
		}
		if !visible {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such instance")
		return
	}
	reply(w, http.StatusOK, in)
}

func (e *Engine) cancelInstance(w http.ResponseWriter, r *http.Request) {
	if !e.isAdmin(r) {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role")
		return
	}
	by, _, _ := who(r)
	if err := e.Cancel(r.Context(), r.PathValue("id"), by); err != nil {
		fail(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"instance": r.PathValue("id"), "status": "cancelled"})
}

func (e *Engine) person(w http.ResponseWriter, r *http.Request) (string, []string, bool) {
	u := heain.UserOf(r.Context())
	if u == nil {
		fail(w, http.StatusForbidden, "forbidden", "tasks are for people (through heain-gateway)")
		return "", nil, false
	}
	return u.ID, u.Roles, true
}

func (e *Engine) inbox(w http.ResponseWriter, r *http.Request) {
	user, roles, ok := e.person(w, r)
	if !ok {
		return
	}
	reply(w, http.StatusOK, map[string]any{"tasks": e.Inbox(user, roles)})
}

func (e *Engine) claim(w http.ResponseWriter, r *http.Request) {
	user, roles, ok := e.person(w, r)
	if !ok {
		return
	}
	t, err := e.Claim(user, roles, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, ErrForbidden):
		fail(w, http.StatusNotFound, "not_found", "no such open task for you")
	case err != nil:
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	default:
		reply(w, http.StatusOK, t)
	}
}

func (e *Engine) complete(w http.ResponseWriter, r *http.Request) {
	user, roles, ok := e.person(w, r)
	if !ok {
		return
	}
	var q struct {
		Outcome string         `json:"outcome"`
		Data    map[string]any `json:"data"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "body: {\"outcome\", \"data\"}")
		return
	}
	t, err := e.Complete(r.Context(), user, roles, r.PathValue("id"), q.Outcome, q.Data)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, ErrForbidden):
		fail(w, http.StatusNotFound, "not_found", "no such task for you")
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		reply(w, http.StatusOK, t)
	}
}
