// Command heain-workflow runs business processes with people in them (Step
// 4.6c). It is configured through the heain-sdk HEAIN_* variables
// (heain.StartFromEnv) plus the flags below, and runs however the operator
// likes: a plain process, a service unit, or a container.
package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-workflow/internal/engine"
	"github.com/heainframework/heain-workflow/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// platform adapts heain-sdk's App to engine.Platform.
type platform struct {
	*heain.App
	der []byte
}

func (p platform) CertDER() []byte { return p.der }

func main() {
	adminCallers := flag.String("admin-callers", os.Getenv("HEAIN_WORKFLOW_ADMIN_CALLERS"), "comma-separated app ids that may manage definitions without a person (people need the workflow-admin role through heain-gateway)")
	notifyApp := flag.String("notify-app", "heain-notify", "the app that sends messages")
	tz := flag.String("timezone", env("HEAIN_WORKFLOW_TZ", "Local"), "time zone of schedules (e.g. Asia/Bangkok)")
	poll := flag.Duration("poll", 3*time.Second, "how often P5 decisions and jobs are checked")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		log.Fatalf("heain-workflow: -timezone: %v", err)
	}

	state := env("HEAIN_STATE_DIR", "/state")
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-workflow: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	inside, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-workflow: data key from core: %v", err)
	}
	st, err := store.Open(filepath.Join(state, "workflow.db"), inside, store.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	blk, _ := pem.Decode(app.CertificatePEM())
	var callers []string
	for _, c := range strings.Split(*adminCallers, ",") {
		if c = strings.TrimSpace(c); c != "" {
			callers = append(callers, c)
		}
	}
	eng := engine.New(&engine.Engine{Store: st, Plat: platform{app, blk.Bytes}, Logf: log.Printf,
		Cfg: engine.Config{AdminCallers: callers, NotifyApp: *notifyApp, Location: loc, PollEvery: *poll}})
	go eng.Run(ctx)
	srv := app.NewServer()
	if err := eng.Register(srv); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", heain.Listen(":19530"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-workflow: active on %s (schedules in %s)", l.Addr(), loc)
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-workflow: deregistered")
}
