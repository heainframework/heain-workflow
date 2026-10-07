// Command wf-demo is an example step app for heain-workflow: it opens
// docs.issue.step (a direct call) and docs.render.step (a core job) to
// workflows. A step receives {workflow, version, instance, step, vars} and
// answers {outcome, vars}.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	var n atomic.Int64
	srv := app.NewServer()
	if err := srv.HandleFunc("POST /v1/issue", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Instance string         `json:"instance"`
			Vars     map[string]any `json:"vars"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(heain.Caller(r.Context()), "heain-workflow.") {
			w.WriteHeader(403)
			return
		}
		outcome := "issued"
		if a, ok := q.Vars["amount"].(float64); ok && a > 1000000 {
			outcome = "too_large" // a step may choose the path
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"outcome": outcome, "vars": map[string]any{"doc": fmt.Sprintf("PO-%04d", n.Add(1))}})
	}); err != nil {
		log.Fatal(err)
	}
	wk := app.NewWorker()
	if err := wk.Handle("docs.render.step", func(ctx context.Context, j *heain.Job) ([]byte, error) {
		var in map[string]any
		_ = json.Unmarshal(j.Payload, &in)
		return json.Marshal(map[string]any{"pages": 3, "rendered_for": in["by"]})
	}); err != nil {
		log.Fatal(err)
	}
	go func() { _ = wk.Run(ctx) }()
	l, err := net.Listen("tcp", heain.Listen(":19531"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("wf-demo: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
}
