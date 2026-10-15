package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/notify"
)

// 二次审核闸门:开了 review_enabled 的任务,「发现新漏洞」的推送必须等审核结论。
//   - 未审  → 事件留在队列里(不 fanned_out),不产生投递
//   - ignored → 事件标记已分派,但**不产生任何投递**(垃圾不推送)
//   - accepted → 正常产生投递
//
// 没开二次审核的任务照旧立即投递。
func TestFanOutHoldsUntilReviewVerdict(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	// 一个启用中的渠道,过滤条件为零值 = 全收。
	enabled := true
	chID, err := d.SaveNotificationChannel(ctx, &NotificationChannel{
		Name: "review-gate-test", Kind: "webhook", Mode: NotifyModeRealtime,
		Config: json.RawMessage(`{}`), Filter: json.RawMessage(`{}`), Enabled: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM notification_channels WHERE id=$1`, chID) })

	// 造 4 条 finding:分别属于「开审核」与「不开审核」任务,结论分别 ignored / accepted / 未审。
	mkTask := func(reviewOn bool) int64 {
		tk, err := d.CreateTask("review-gate", "gate test", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if reviewOn {
			if _, err := d.Exec(`UPDATE tasks SET review_enabled=true WHERE id=$1`, tk.ID); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, tk.ID) })
		return tk.ID
	}
	mkFinding := func(taskID int64, name string) int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO findings(task_id, vulnclass, name, severity, summary, evidence)
VALUES($1,'test',$2,'low','gate test summary','gate test evidence') RETURNING id`, taskID, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DELETE FROM notification_events WHERE finding_id=$1`, id)
			_, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, id)
		})
		return id
	}

	reviewTask := mkTask(true)
	plainTask := mkTask(false)

	// 事件必须由测试自己造:正常写入路径只在真实报告漏洞时插事件。
	addEvent := func(findingID int64, name string) int64 {
		snap := notify.Snapshot{Kind: notify.EventFindingCreated, FindingID: findingID, Severity: "low", VulnClass: "test", Name: name}
		raw, _ := json.Marshal(snap)
		var id int64
		if err := d.QueryRowContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot)
VALUES($1,$2,$3) RETURNING id`, notify.EventFindingCreated, findingID, string(raw)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	heldFinding := mkFinding(reviewTask, "held-unreviewed")
	ignoredFinding := mkFinding(reviewTask, "ignored-junk")
	acceptedFinding := mkFinding(reviewTask, "accepted-real")
	plainFinding := mkFinding(plainTask, "no-review-immediate")

	heldEv := addEvent(heldFinding, "held-unreviewed")
	ignoredEv := addEvent(ignoredFinding, "ignored-junk")
	acceptedEv := addEvent(acceptedFinding, "accepted-real")
	plainEv := addEvent(plainFinding, "no-review-immediate")

	// 只给 accepted 那条写审核结论;ignored 那条写 ignored。
	if err := d.SetFindingReview(ignoredFinding, FindingReview{Verdict: ReviewVerdictIgnored, Severity: "low", Reasons: "junk"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetFindingReview(acceptedFinding, FindingReview{Verdict: ReviewVerdictAccepted, Severity: "high", Reasons: ""}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := d.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}

	state := func(eventID int64) (fanned bool, deliveries int) {
		if err := d.QueryRow(`SELECT fanned_out FROM notification_events WHERE id=$1`, eventID).Scan(&fanned); err != nil {
			t.Fatal(err)
		}
		if err := d.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE event_id=$1`, eventID).Scan(&deliveries); err != nil {
			t.Fatal(err)
		}
		return
	}

	// 未审 → 留在队列里等结论,不投递。
	if fanned, del := state(heldEv); fanned || del != 0 {
		t.Errorf("未审事件应继续等待(fanned=false, 0 投递), got fanned=%v deliveries=%d", fanned, del)
	}
	// ignored → 已分派但零投递(垃圾不推送)。
	if fanned, del := state(ignoredEv); !fanned || del != 0 {
		t.Errorf("ignored 事件应标记已分派但零投递, got fanned=%v deliveries=%d", fanned, del)
	}
	// accepted → 正常投递。
	if fanned, del := state(acceptedEv); !fanned || del == 0 {
		t.Errorf("accepted 事件应正常投递, got fanned=%v deliveries=%d", fanned, del)
	}
	// 没开审核 → 立即投递,不受闸门影响。
	if fanned, del := state(plainEv); !fanned || del == 0 {
		t.Errorf("未开审核的任务应立即投递, got fanned=%v deliveries=%d", fanned, del)
	}
}
