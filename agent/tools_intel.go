package agent

// tools_intel.go —— 全局情报库检索工具(schema §O / db/intel.go)。
// 参考 AutoHunter 的 intel 库:一个任务里验证过的凭据、确认的漏洞特征、发现的端点,
// 沉淀成全局条目;后续任务先查库再开打,不必从零开始。

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// clipIntel 截断情报文本(按字符)。
func clipIntel(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// intelTool 检索全局情报库。
func (t *ToolSet) intelTool() actool.CoreTool {
	return readTool(
		"search_intel",
		"检索全局情报库(跨任务可复用):别的任务里验证过的凭据线索、确认过的漏洞特征、发现过的端点、目标画像。\n"+
			"开打前先查一下:目标可能已在别的任务里被验证过,避免从零重复探测。\n"+
			"kind: cred(凭据线索:用户名@域+类型+主机,不含明文密钥) / fingerprint(漏洞特征:归一化 vulnclass) / endpoint(端点:method url) / profile(目标画像);省略=all。\n"+
			"q 在 key/value 上大小写不敏感子串匹配;省略 q 返回最热/最近条目。",
		obj(map[string]any{
			"kind":  str("情报类型: cred | fingerprint | endpoint | profile;省略=all"),
			"q":     str("关键词(在 key/value 上大小写不敏感子串匹配);省略=返回最热条目"),
			"limit": intp("返回条数,默认 10,上限 50"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.is == nil {
				return actool.Errorf("search_intel 未接入: intel store 未初始化"), nil
			}
			var a struct {
				Kind  string `json:"kind"`
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}
			if a.Limit > 50 {
				a.Limit = 50
			}
			recs, err := t.is.SearchIntel(ctx, a.Kind, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf("检索情报失败: " + err.Error()), nil
			}
			// 命中计数(最佳努力,不影响返回)。
			if len(recs) > 0 {
				ids := make([]int64, 0, len(recs))
				for _, r := range recs {
					ids = append(ids, r.ID)
				}
				_ = t.is.TouchIntel(ctx, ids)
			}
			items := make([]map[string]any, 0, len(recs))
			for _, r := range recs {
				items = append(items, map[string]any{
					"kind": r.Kind, "key": r.Key,
					"value":      clipIntel(r.Value, 300),
					"confidence": r.Confidence, "hits": r.Hits,
					"source_task_id": r.SourceTaskID, "source": r.Source,
					"updated_at": r.UpdatedAt,
				})
			}
			return jsonResult(map[string]any{
				"count": len(items), "intel": items,
				"note": "跨任务复用的既有情报;先看这里再决定是否重复探测/利用。cred 条目只给类型+主机+credential id,不含明文密钥(list_credentials 取详情)。",
			})
		})
}
