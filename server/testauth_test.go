package server

import (
	"net/http"
)

// baAuth 给测试请求挂上服务端签名的 BA 会话 Cookie —— 等价于"用户已用 Basic Auth 登录"。
//
// 背景:认证从 JWT Bearer 改成 Basic Auth + 会话 Cookie 之后,requireAuth 只认
// ?ticket= / BA 会话 Cookie / HTTP Basic,**不再接受 Authorization: Bearer**。
// 而 14 个 HTTP 测试文件仍发 Bearer,于是全部 401 —— HTTP 层等于失去回归保护。
//
// 这里直接用服务端自己的签名函数造 Cookie:不写 DB、不需要真实密码,也不依赖
// Basic Auth 的 bcrypt 校验,是让既有 HTTP 测试重新跑起来的最小改动。
func baAuth(s *Server, r *http.Request) {
	if s == nil || r == nil {
		return
	}
	r.AddCookie(&http.Cookie{Name: baSessCookieName, Value: s.signBASession()})
}
