package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	MaxTaskTemplateNameRunes = 120
	MaxTaskTemplateTextRunes = 16000
)

var (
	ErrTaskTemplateInvalid      = errors.New("invalid task template")
	ErrTaskTemplateBuiltin      = errors.New("built-in task template is protected")
	ErrTaskTemplateNameConflict = errors.New("task template name already exists")
	ErrTaskTemplateNotFound     = errors.New("task template not found")
)

// TaskTemplate is a reusable task preset (description/goal + optional category
// and task-level intercept/allow rules).
type TaskTemplate struct {
	ID             int64                    `json:"id"`
	Name           string                   `json:"name"`
	NKey           string                   `json:"-"`
	Description    string                   `json:"description"`
	Goal           string                   `json:"goal"`
	CategoryID     *int64                   `json:"category_id"`
	InterceptRules []TaskInterceptRuleInput `json:"intercept_rules"`
	Builtin        bool                     `json:"builtin"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

// TaskTemplateInput is the create/update payload after normalization.
type TaskTemplateInput struct {
	Name           string
	Description    string
	Goal           string
	CategoryID     *int64
	InterceptRules []TaskInterceptRuleInput
}

// TaskTemplatePatch changes only fields flagged as set. Name/Description/Goal use
// non-nil pointers; CategoryID/InterceptRules use explicit Set flags (so a nil
// CategoryID can mean "clear" when SetCategoryID is true).
type TaskTemplatePatch struct {
	Name              *string
	Description       *string
	Goal              *string
	CategoryID        *int64
	SetCategoryID     bool
	InterceptRules    []TaskInterceptRuleInput
	SetInterceptRules bool
}

const taskTemplateCols = `id, name, nkey, description, goal, category_id, intercept_rules, created_at, updated_at, builtin`

func scanTaskTemplate(row interface{ Scan(...any) error }) (TaskTemplate, error) {
	var t TaskTemplate
	var rulesRaw []byte
	if err := row.Scan(&t.ID, &t.Name, &t.NKey, &t.Description, &t.Goal, &t.CategoryID, &rulesRaw, &t.CreatedAt, &t.UpdatedAt, &t.Builtin); err != nil {
		return t, err
	}
	t.InterceptRules = []TaskInterceptRuleInput{}
	if len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &t.InterceptRules); err != nil {
			return t, err
		}
		if t.InterceptRules == nil {
			t.InterceptRules = []TaskInterceptRuleInput{}
		}
	}
	return t, nil
}

// marshalTemplateRules serializes a template's rule snapshot to JSONB text,
// always producing a JSON array (never null).
func marshalTemplateRules(rules []TaskInterceptRuleInput) ([]byte, error) {
	if rules == nil {
		rules = []TaskInterceptRuleInput{}
	}
	return json.Marshal(rules)
}

// taskTemplateName normalizes display whitespace while preserving the user's case.
func taskTemplateName(name string) string { return strings.Join(strings.Fields(name), " ") }

// taskTemplateNKey is the case-insensitive identity used by the unique index.
func taskTemplateNKey(name string) string { return strings.ToLower(taskTemplateName(name)) }

func normalizeTaskTemplateInput(in TaskTemplateInput) (TaskTemplateInput, string, error) {
	in.Name = taskTemplateName(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Goal = strings.TrimSpace(in.Goal)
	switch {
	case in.Name == "":
		return in, "", fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Name) > MaxTaskTemplateNameRunes:
		return in, "", fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
	case in.Description == "":
		return in, "", fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Description) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	case in.Goal == "":
		return in, "", fmt.Errorf("%w: goal is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Goal) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	}
	return in, taskTemplateNKey(in.Name), nil
}

func normalizeTaskTemplatePatch(patch TaskTemplatePatch) (TaskTemplatePatch, *string, error) {
	if patch.Name == nil && patch.Description == nil && patch.Goal == nil && !patch.SetCategoryID && !patch.SetInterceptRules {
		return patch, nil, fmt.Errorf("%w: no fields supplied", ErrTaskTemplateInvalid)
	}
	var nkey *string
	if patch.Name != nil {
		name := taskTemplateName(*patch.Name)
		if name == "" {
			return patch, nil, fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(name) > MaxTaskTemplateNameRunes {
			return patch, nil, fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
		}
		key := taskTemplateNKey(name)
		patch.Name = &name
		nkey = &key
	}
	if patch.Description != nil {
		description := strings.TrimSpace(*patch.Description)
		if description == "" {
			return patch, nil, fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(description) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Description = &description
	}
	if patch.Goal != nil {
		goal := strings.TrimSpace(*patch.Goal)
		if goal == "" {
			return patch, nil, fmt.Errorf("%w: goal is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(goal) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Goal = &goal
	}
	return patch, nkey, nil
}

func taskTemplateUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateTaskTemplate inserts one globally reusable preset.
func (d *DB) CreateTaskTemplate(in TaskTemplateInput) (*TaskTemplate, error) {
	in, nkey, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(in.InterceptRules)
	if err != nil {
		return nil, err
	}
	t, err := scanTaskTemplate(d.QueryRow(`
INSERT INTO task_templates(name, nkey, description, goal, category_id, intercept_rules)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (nkey) DO NOTHING
RETURNING `+taskTemplateCols, in.Name, nkey, in.Description, in.Goal, in.CategoryID, rulesJSON))
	if err == sql.ErrNoRows {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTaskTemplates returns the most recently maintained templates first.
func (d *DB) ListTaskTemplates() ([]*TaskTemplate, error) {
	rows, err := d.Query(`SELECT ` + taskTemplateCols + ` FROM task_templates ORDER BY builtin DESC, updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TaskTemplate{}
	for rows.Next() {
		t, err := scanTaskTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// GetTaskTemplate returns nil when id does not exist.
func (d *DB) GetTaskTemplate(id int64) (*TaskTemplate, error) {
	t, err := scanTaskTemplate(d.QueryRow(`SELECT `+taskTemplateCols+` FROM task_templates WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// UpdateTaskTemplate replaces the editable fields of one preset.
func (d *DB) UpdateTaskTemplate(id int64, in TaskTemplateInput) (*TaskTemplate, error) {
	in, _, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	return d.PatchTaskTemplate(id, TaskTemplatePatch{
		Name: &in.Name, Description: &in.Description, Goal: &in.Goal,
	})
}

// PatchTaskTemplate atomically changes only the supplied fields. Keeping the
// merge in one UPDATE prevents concurrent disjoint PATCH requests from losing
// each other's changes.
func (d *DB) PatchTaskTemplate(id int64, patch TaskTemplatePatch) (*TaskTemplate, error) {
	patch, nkey, err := normalizeTaskTemplatePatch(patch)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(patch.InterceptRules)
	if err != nil {
		return nil, err
	}
	t, err := scanTaskTemplate(d.QueryRow(`UPDATE task_templates
SET name=CASE WHEN $2 THEN $3::text ELSE name END,
    nkey=CASE WHEN $2 THEN $4::text ELSE nkey END,
    description=CASE WHEN $5 THEN $6::text ELSE description END,
    goal=CASE WHEN $7 THEN $8::text ELSE goal END,
    category_id=CASE WHEN $9 THEN $10::bigint ELSE category_id END,
    intercept_rules=CASE WHEN $11 THEN $12::jsonb ELSE intercept_rules END
WHERE id=$1 AND (NOT builtin OR NOT $2 OR nkey = $4::text)
RETURNING `+taskTemplateCols,
		id,
		patch.Name != nil, patch.Name, nkey,
		patch.Description != nil, patch.Description,
		patch.Goal != nil, patch.Goal,
		patch.SetCategoryID, patch.CategoryID,
		patch.SetInterceptRules, rulesJSON,
	))
	if err == sql.ErrNoRows {
		// Either the id is gone, or it is a built-in preset and the caller tried to rename it.
		var builtin bool
		if qerr := d.QueryRow(`SELECT builtin FROM task_templates WHERE id=$1`, id).Scan(&builtin); qerr == nil && builtin {
			return nil, ErrTaskTemplateBuiltin
		}
		return nil, ErrTaskTemplateNotFound
	}
	if taskTemplateUniqueViolation(err) {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTaskTemplate deletes one preset and reports whether it existed.
// DeleteTaskTemplate deletes one user preset and reports whether it existed.
// Built-in presets (CTF/SRC) are protected and cannot be removed.
func (d *DB) DeleteTaskTemplate(id int64) (bool, error) {
	var builtin bool
	err := d.QueryRow(`SELECT builtin FROM task_templates WHERE id=$1`, id).Scan(&builtin)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if builtin {
		return false, ErrTaskTemplateBuiltin
	}
	result, err := d.Exec(`DELETE FROM task_templates WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}

// builtinTaskTemplates 是随程序发布的内置任务模板正文。描述/目标可被用户改写，
// 但名称与存在性受保护(不可改名/删除)，每次启动幂等补齐。
var builtinTaskTemplates = []struct {
	Name        string
	Description string
	Goal        string
}{
	{
		Name:        "CTF",
		Description: "CTF 竞赛 / 靶场场景：目标处于隔离比赛环境，允许为解题放开手脚做高强度利用与破坏性操作（打点、提权、横向、拿 flag），不承担业务影响。",
		Goal: `在隔离的 CTF / 靶场环境中解题并拿到 flag。这是比赛/靶场场景，可以放开手脚：

1. 侦察定面：枚举端口与服务、Web 路径与参数、指纹与已知漏洞版本，先把攻击面铺开。
2. 漏洞利用：对确认的漏洞直接利用（RCE、反序列化、文件包含、SQL 注入、越权、模板注入等），必要时上传工具、写 webshell、提权。
3. 后利用与横向：允许内网横向、抓取凭据、读取任意文件，以拿到最终目标（flag / 域控 / 隐藏关卡）为准。
4. 破坏性操作允许：可以改配置、重启服务、清理痕迹，比赛环境不追求业务连续性。
5. 交付：写清完整利用链、每步用的命令与 payload、拿到的 flag 原文及其位置；未打通的部分标注卡点与已排除的路径。

纪律：以最快拿到 flag 为第一目标，不要停在信息收集；每条结论都要附实际命令与回显，禁止虚构结果。`,
	},
	{
		Name:        "SRC",
		Description: "SRC / 众测 / 漏洞赏金场景：只在授权范围内做漏洞验证，强调边界——证明漏洞存在即可，禁止破坏性操作与深入利用（不取数据、不上传 webshell、不横向、不驻留）。",
		Goal: `在授权的 SRC / 众测范围内做漏洞验证与提交，核心是「边界」。

【授权范围】先确认并严格遵守：允许的域名 / IP / 端口 / 子域、允许的时间窗、允许的测试类型。范围外的资产一律不碰。

【验证尺度】最小化验证：用能证明漏洞存在的最少请求即可，拿到 PoC 证据就停。
- 只读优先：SQL 注入用布尔 / 时间盲注或只读探测证明，不 dump 数据；命令执行用 id / whoami 等无害命令证明，不读敏感文件、不留后门。
- 越权 / IDOR：只取「能证明越权」的最小样本，不对真实用户数据做批量遍历。
- 上传：只上传无害标记文件证明可上传，不上传 webshell、不留可执行后门。

【明确禁止（红线）】
- 不拖库、不篡改或删除业务数据、不修改目标配置。
- 不上传 webshell / 不部署隧道 / 不横向移动 / 不驻留 / 不创建账号。
- 不做 DoS / 压测 / 高频爆破，不干扰业务可用性。
- 不碰范围外资产，不碰真实用户隐私数据；若不可避免，立即停止并在报告中说明。

【处置与交付】
- 发现高危（可直接接管、可拖库等）立即停止深入，只保留证明所需证据。
- 记录：URL、参数、请求 / 响应片段（敏感信息脱敏）、复现步骤、影响说明、修复建议。
- 按平台规范分级提交；不能确认或影响无法自证的问题标注为「存疑」，不夸大。

【边界优先】任何一步拿不准是否越界，就先停下、只做到能证明为止，不要为了「打得深」而突破边界。`,
	},
}

// seedBuiltinTaskTemplates 幂等播种内置模板(CTF/SRC)：同名模板只重申 builtin 标记，
// 不覆盖用户对描述/目标的修改；被删除后下次启动会重新补齐。
func (d *DB) seedBuiltinTaskTemplates() error {
	for _, t := range builtinTaskTemplates {
		if _, err := d.Exec(`
INSERT INTO task_templates(name, nkey, description, goal, builtin)
VALUES ($1,$2,$3,$4,true)
ON CONFLICT (nkey) DO UPDATE SET builtin = true`,
			t.Name, taskTemplateNKey(t.Name), t.Description, t.Goal); err != nil {
			return fmt.Errorf("builtin template %q: %w", t.Name, err)
		}
	}
	return nil
}
