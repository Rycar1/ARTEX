package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// ---------------------------------------------------------------------------
// 卡住时的「高级顾问」(P0-1,对齐 PentAGI 的 execution monitor / mentor)。
//
// 背景:原来的停滞检测只注入一句固定纪律(「立即停止同轴重试:要么换维度…」)。
// 那句话能叫停,但**给不出该换到哪去** —— 而"换到哪去"正是卡住时最需要的信息。
// PentAGI 的做法是另起一个 agent(mentor)看全局给策略建议,自述「2-3x 成本换 2x 质量」。
//
// 这里把它落成一次**带全局上下文的副作用 LLM 调用**:顾问能看到任务目标、当前意图、
// 卡住的形态(同质响应/连续失败 + 签名 + 次数)、平台已给的类别化转向建议、最近试过的
// 工具序列、以及这是第几次触发,产出一段**具体**的转向指令替换掉原来的固定文本。
//
// 三条纪律:
//  1. **只换建议、不换判据**:触发仍由 StuckDetector 的确定性判据决定,顾问只负责
//     "往哪走"。顾问不可用(未接入/调用失败/超时)时**原样保留**固定纪律,绝不因为
//     顾问挂了就不干预。
//  2. **不许臆造**:顾问只能基于给定上下文判断,上下文里没出现的东西不准编。
//  3. **必须可执行**:产出要落到"换哪个维度 + 为什么 + 下一步具体做什么",不接受
//     "建议换个思路"这类空话;判定该方向确已榨干时,要明确说收尾并给出新方向。
// ---------------------------------------------------------------------------

// StuckAdviceRequest 是向顾问求助时提供的上下文(全部来自平台已观测到的事实)。
type StuckAdviceRequest struct {
	Goal        string // 任务目标(可能为空)
	Intent      string // 当前意图正文(worker 这一棒的唯一职责)
	Stuck       StuckEvent
	PivotHint   string   // 平台按意图类别给的转向建议(chainskel.PivotHints),可能为空
	RecentTools []string // 最近若干次工具名(新到旧),让顾问看到"试过什么"
	PriorFires  int      // 本意图此前已触发过几次(含本次)
	Coverage    string   // 可选:覆盖/资产等补充态势
}

// StuckAdviser 用一次非流式 LLM 调用产出卡住时的转向建议。
// 无状态、可复用;prov 为 nil 时 Advise 直接返回错误(调用方保留固定干预)。
type StuckAdviser struct {
	prov      llm.Provider
	maxTokens int
	timeout   time.Duration
}

// NewStuckAdviser 构造顾问。prov 必须非 nil 才有意义(调用方负责判空)。
func NewStuckAdviser(prov llm.Provider) *StuckAdviser {
	return &StuckAdviser{prov: prov, maxTokens: 700, timeout: 60 * time.Second}
}

// Available 报告顾问是否可用(未接入 provider = 不可用)。
func (a *StuckAdviser) Available() bool { return a != nil && a.prov != nil }

// stuckAdviserPrompt 是顾问的系统提示词。
//
// 与 worker 的常规提示词分工:worker 管执行,顾问管"卡住时判断该换到哪去"。它拿不到
// 工具、也不执行任何动作 —— 产出只是一段给 worker 的指令文本。
const stuckAdviserPrompt = `你是授权渗透测试平台的「高级顾问」,在一线 worker 卡住时被唤起。你的唯一职责:
根据平台给出的**已观测事实**,判断 worker 该换到哪个维度,并给出一段**具体可执行**的转向指令。

# 判据(先读这段)
worker 被判「信息梯度为零」有两种形态:
- same_signature:连续多次工具响应的**归一化内容完全一致**(平台已剥离时间戳/路径/随机串)。
  含义:同样的动作得到同样的结果,再试同轴不会产生新信息。
- same_tool_failure:同一工具**连续多次失败且输出高度相似**。
  含义:要么参数/信道不对,要么这条路本身不通,要么被统一拦截层挡住。

# 你必须输出的东西
一段**给 worker 的指令**,包含三部分(总长 200~400 字,中文,不要寒暄):
1. **判断**:这次卡住最可能是什么原因(被统一拦截层挡?参数维度没换?工具选错?方向确实已榨干?
   目标不可达?)。只依据给定事实,说不准就明说"不确定,优先用下面第 2 条的第一步验证"。
2. **换哪个维度**:给 2~3 条**互不同轴**的具体方向。维度指:参数/编码、信道(协议/端口/方法)、
   入口(接口/路径/子域)、漏洞类、身份/凭据、工具。每条要写清**具体做什么**(例如
   "把注入点从 query 换到 JSON body 的嵌套字段",而不是"换个参数试试")。
3. **下一步动作**:一句话说明**先做哪一条、用什么工具/命令验证**,以及"出现什么结果算这条路通"。

# 铁律
- **不得臆造**:上下文里没出现的接口、参数、凭据、版本一律不准编。信息不足时,把"先探测什么来补齐信息"
  作为第一条方向。
- **不得空话**:"换个思路/再试试/仔细检查"这类没有动作的句子等于没给建议。
- **该收尾就说收尾**:若事实表明这个方向确实已榨干(例如目标根本不提供该功能、统一拦截层对所有
  变体一致响应),明确说"该方向榨干,建议写回 fact 收尾",并指出**应该转向哪个新方向**。
- **不要提问、不要请求确认**:你给的是指令,worker 会直接执行。
- 只输出指令正文,不要输出标题、编号列表以外的解释。`

// Advise 产出一次转向建议。失败(未接入/超时/空回复)时返回错误,调用方保留原有固定干预。
func (a *StuckAdviser) Advise(ctx context.Context, req StuckAdviceRequest) (string, error) {
	if !a.Available() {
		return "", fmt.Errorf("顾问未接入 provider")
	}
	cctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	out, _, _, err := a.prov.Complete(cctx, llm.CompletionRequest{
		System:    []string{stuckAdviserPrompt},
		Messages:  []llm.Message{llm.UserText(buildStuckAdviceInput(req))},
		MaxTokens: a.maxTokens,
		Thinking:  "disabled", // 顾问只要结论,不需要推理链,省 token
	})
	if err != nil {
		return "", err
	}
	advice := strings.TrimSpace(out.Text())
	if advice == "" {
		return "", fmt.Errorf("顾问返回空建议")
	}
	return advice, nil
}

// buildStuckAdviceInput 把上下文渲染成顾问的输入。字段全部来自平台已观测事实,
// 空字段显式标注"(未知)",避免顾问把缺失当成"没有"。
func buildStuckAdviceInput(req StuckAdviceRequest) string {
	var sb strings.Builder
	sb.WriteString("【任务目标】\n")
	sb.WriteString(orUnknown(req.Goal))
	sb.WriteString("\n\n【当前意图(worker 这一棒的唯一职责)】\n")
	sb.WriteString(orUnknown(req.Intent))

	sb.WriteString("\n\n【卡住事实】\n")
	kind := "连续多次响应完全同质(同轴重试不产生新信息)"
	if req.Stuck.Kind == "same_tool_failure" {
		kind = "同一工具连续失败且输出高度相似"
	}
	fmt.Fprintf(&sb, "- 形态:%s\n- 连续次数:%d\n- 工具:%s\n- 响应签名(归一化后内容指纹):%s\n- 本意图第 %d 次触发\n",
		kind, req.Stuck.Count, orUnknown(req.Stuck.Tool), req.Stuck.Signature, req.PriorFires)

	if len(req.RecentTools) > 0 {
		sb.WriteString("\n【最近试过的工具(新到旧)】\n")
		sb.WriteString(strings.Join(req.RecentTools, " → "))
		sb.WriteString("\n")
	}
	if strings.TrimSpace(req.PivotHint) != "" {
		sb.WriteString("\n【平台按本意图类别预先给出的转向建议(参考,不是命令)】\n")
		sb.WriteString(strings.TrimSpace(req.PivotHint))
		sb.WriteString("\n")
	}
	if strings.TrimSpace(req.Coverage) != "" {
		sb.WriteString("\n【补充态势】\n")
		sb.WriteString(strings.TrimSpace(req.Coverage))
		sb.WriteString("\n")
	}
	sb.WriteString("\n请按系统提示的要求,给出给 worker 的转向指令正文。")
	return sb.String()
}

func orUnknown(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return "(未知)"
	}
	return s
}
