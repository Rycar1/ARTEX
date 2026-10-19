package db

import "testing"

// openCreateTaskDB 打开测试库(与 db 包其它用例同一套 testDSN 约定)。
func openCreateTaskDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return d
}

// TestCreateTaskWithOptionsReturnsUnattended 复现「新建任务后无人值守不生效」的根因:
//
// CreateTaskWithOptions 把 opts.Unattended 写进了 DB,但返回给调用方的 *Task 是从
// 内存结构体直接构造的(只从 RETURNING 回填 id/status/paused/created_at),漏赋值
// 就会出现「库里 unattended=t、内存 Task.Unattended=false」。
// 服务端的任务级开关解析器读的就是这个内存 Task,于是新建任务后立刻跑时,
// 无人值守读不到 true,照样建审批单等人。
func TestCreateTaskWithOptionsReturnsUnattended(t *testing.T) {
	d := openCreateTaskDB(t)
	defer d.Close()

	for _, want := range []bool{true, false} {
		task, err := d.CreateTaskWithOptions("unattended-return", "goal", TaskCreateOptions{
			Name:       "unattended-return",
			Unattended: want,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

		if task.Unattended != want {
			t.Fatalf("CreateTaskWithOptions 返回的 Task.Unattended = %v,期望 %v(内存与库不一致会导致任务级开关失效)",
				task.Unattended, want)
		}
		// 库里的值也必须是同一个,确认不是「只有内存对」。
		var stored bool
		if err := d.QueryRow(`SELECT unattended FROM tasks WHERE id=$1`, task.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != want {
			t.Fatalf("tasks.unattended = %v,期望 %v", stored, want)
		}
	}
}

// TestCreateTaskWithOptionsReturnsOpMode 同一类问题的回归保护:OpMode 也是
// 「写库 + 返回内存结构体」的字段,激进模式的任务级判定同样依赖它。
func TestCreateTaskWithOptionsReturnsOpMode(t *testing.T) {
	d := openCreateTaskDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("opmode-return", "goal", TaskCreateOptions{
		Name:   "opmode-return",
		OpMode: "aggressive",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	if task.OpMode != "aggressive" {
		t.Fatalf("返回的 Task.OpMode = %q,期望 aggressive", task.OpMode)
	}
}
