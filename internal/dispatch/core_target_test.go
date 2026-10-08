package dispatch_test

import (
	"context"
	"testing"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

// TestATaskNamingCoreIsRefusedEvenWhenTheScopeAllowsIt is ADR-110's site-one
// half. The seeded task targets 192.0.2.7, which the seed's policy ALLOWS - so
// the only thing that can refuse it is the Core check. Core's endpoints are
// exempt from the Scan Point's kernel packet ceiling; a scan of one would run
// outside the ceiling, so it must never be dispatched.
//
// mutate:subject internal/dispatch/dispatch.go
// mutate:test    ./internal/dispatch/ -run TestATaskNamingCoreIsRefusedEvenWhenTheScopeAllowsIt
// mutate:case    Core consults only the scope rules, so a task naming a Core endpoint is dispatched
// mutate:old     case canonical && s.core.Contains(canon):
// mutate:new     case false && s.core.Contains(canon):
func TestATaskNamingCoreIsRefusedEvenWhenTheScopeAllowsIt(t *testing.T) {
	db := testDB(t)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID := seedQueuedJob(t, db, tenant, true)

	core, err := target.NewCoreEndpoints(context.Background(), []string{"192.0.2.7:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, db)
	svc.SetCoreEndpoints(core)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	done := make(chan error, 1)
	go func() { done <- svc.Connect(fs) }()

	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId:     spID.String(),
			ProtocolVersion: testVersion,
			AgentVersion:    "0.1.0",
			Capabilities: []*scanpointv1.Capability{
				{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true},
			},
		}},
	})
	fs.waitFor(t, "ServerHello", func(m *scanpointv1.CoreMessage) bool {
		return m.GetServerHello() != nil
	})

	deadline := time.Now().Add(10 * time.Second)
	var terminal *store.Job
	for time.Now().Before(deadline) && terminal == nil {
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
			if err != nil {
				return err
			}
			if j.Status == store.JobFailed {
				terminal = j
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if terminal == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	cancel()
	<-done

	if terminal == nil {
		t.Fatal("a job targeting a Core endpoint was not refused (ADR-110)")
	}
	if terminal.TerminationReason == nil || *terminal.TerminationReason != store.TerminationScopeViolationHalt {
		t.Errorf("termination_reason = %v, want scope_violation_halt", terminal.TerminationReason)
	}
	fs.mu.Lock()
	outbound := append([]*scanpointv1.CoreMessage(nil), fs.outbound...)
	fs.mu.Unlock()
	for _, m := range outbound {
		if m.GetJob() != nil {
			t.Errorf("a job targeting Core was put on the wire: %v", m.GetJob())
		}
	}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", jobID, 10)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.Action == "job.scope_refused" {
				return nil
			}
		}
		t.Errorf("no job.scope_refused audit event; got %d events", len(events))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
