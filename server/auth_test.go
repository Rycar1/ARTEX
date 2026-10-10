package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

// memKV 是 authKV 的内存实现,F6 的 auth 测试不依赖 PostgreSQL。
type memKV struct {
	mu  sync.Mutex
	m   map[string]string
	err error // 注入存储错误,验证 fail-closed
}

func newMemKV() *memKV { return &memKV{m: map[string]string{}} }

func (k *memKV) GetSetting(key string) (string, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return "", false, k.err
	}
	v, ok := k.m[key]
	return v, ok, nil
}

func (k *memKV) SetSetting(key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return k.err
	}
	k.m[key] = value
	return nil
}

func (k *memKV) DeleteSetting(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return k.err
	}
	delete(k.m, key)
	return nil
}

var testJWTKey = []byte("0123456789abcdef0123456789abcdef")

func TestAccessTokenVersionRevocation(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}

	tok, err := signJWT(testJWTKey, 0)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !s.validAccessToken(tok) {
		t.Fatal("fresh token (ver 0, unset setting) should validate")
	}

	// 改密 → 版本 +1 → 旧 token 立即失效
	if _, err := bumpAuthKeyVersion(kv); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if s.validAccessToken(tok) {
		t.Fatal("token signed under old version must be rejected after bump")
	}

	// 新版本签发的 token 通过
	tok2, err := signJWT(testJWTKey, 1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !s.validAccessToken(tok2) {
		t.Fatal("token signed under current version should validate")
	}

	// 错 key / 篡改直接拒
	if s.validAccessToken(tok2 + "x") {
		t.Fatal("tampered token must be rejected")
	}
	other, err := signJWT([]byte("fedcba9876543210fedcba9876543210"), 1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if s.validAccessToken(other) {
		t.Fatal("token signed with a different key must be rejected")
	}

	// 存储错误 fail-closed
	kv.err = errTest
	if s.validAccessToken(tok2) {
		t.Fatal("version read failure must fail closed")
	}
	kv.err = nil

	// 无持久层时只做签名+过期校验(降级路径)
	s2 := &Server{jwtKey: testJWTKey}
	if !s2.validAccessToken(tok2) {
		t.Fatal("nil store should fall back to signature/expiry validation")
	}
}

var errTest = &testError{"injected store error"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func TestRefreshTokenLifecycle(t *testing.T) {
	kv := newMemKV()

	rt, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(rt) < 40 {
		t.Fatalf("refresh token too short: %d chars", len(rt))
	}
	// 落库的是哈希,不是原文
	if _, ok, _ := kv.GetSetting(refreshSettingKey(rt)); ok {
		t.Fatal("refresh token must be stored hashed, not in clear")
	}
	if _, ok := validateRefreshToken(kv, rt, 0); !ok {
		t.Fatal("fresh refresh token should validate")
	}
	// 未知 token / 版本不符 一律拒
	if _, ok := validateRefreshToken(kv, rt+"x", 0); ok {
		t.Fatal("unknown refresh token must be rejected")
	}
	if _, ok := validateRefreshToken(kv, rt, 1); ok {
		t.Fatal("refresh token from old version must be rejected after bump")
	}

	// 旋转(滑动续期):旧票作废,新票有效且过期时间重置
	before := time.Now().Add(refreshTTL).Unix()
	if err := kv.DeleteSetting(refreshSettingKey(hashRefreshToken(rt))); err != nil {
		t.Fatalf("rotate delete: %v", err)
	}
	if _, ok := validateRefreshToken(kv, rt, 0); ok {
		t.Fatal("rotated-out refresh token must be rejected (replay protection)")
	}
	rt2, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	rec, ok := validateRefreshToken(kv, rt2, 0)
	if !ok {
		t.Fatal("rotated refresh token should validate")
	}
	if rec.Exp < before {
		t.Fatalf("sliding renewal should reset expiry: got %d, want >= %d", rec.Exp, before)
	}
}

func TestRefreshTokenExpiry(t *testing.T) {
	kv := newMemKV()
	rt, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// 手动把记录改成已过期
	expired, _ := json.Marshal(refreshRecord{Exp: time.Now().Add(-time.Hour).Unix(), Ver: 0})
	if err := kv.SetSetting(refreshSettingKey(hashRefreshToken(rt)), string(expired)); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, ok := validateRefreshToken(kv, rt, 0); ok {
		t.Fatal("expired refresh token must be rejected")
	}
}

func TestSSETicketSingleUseAndExpiry(t *testing.T) {
	store := &sseTicketStore{}
	tok, err := store.issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !store.consume(tok) {
		t.Fatal("first consume should succeed")
	}
	if store.consume(tok) {
		t.Fatal("second consume must fail (one-time use)")
	}
	if store.consume("nonexistent") {
		t.Fatal("unknown ticket must fail")
	}

	// 过期票据:直接往 map 里塞一个已过期的
	tok2, err := store.issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	store.mu.Lock()
	store.m[tok2] = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if store.consume(tok2) {
		t.Fatal("expired ticket must fail")
	}
}

func TestRequireAuthTicketPath(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	ok := false
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ok = true
		w.WriteHeader(200)
	}))

	// 无凭证 → 401
	r := httptest.NewRequest("GET", "/api/anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("no credentials: want 401, got %d", rec.Code)
	}

	// ?token= 已移除 → 401
	tokJWT, _ := signJWT(testJWTKey, 0)
	r = httptest.NewRequest("GET", "/api/anything?token="+tokJWT, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("?token= must no longer authenticate: got %d", rec.Code)
	}

	// Basic Auth → 200 + Set-Cookie
	kv.SetSetting("auth.password_hash", string(func() []byte {
		h, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
		return h
	}()))
	r = httptest.NewRequest("GET", "/api/anything", nil)
	r.SetBasicAuth("ARTEX", "testpass123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || !ok {
		t.Fatalf("basic auth: want 200, got %d (ok=%v)", rec.Code, ok)
	}
	var sessCookie *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "artex_ba_sess" {
			sessCookie = ck
			break
		}
	}
	if sessCookie == nil {
		t.Fatal("basic auth success must set artex_ba_sess cookie")
	}

	// Session cookie alone → 200 (no re-prompt)
	ok = false
	r2 := httptest.NewRequest("GET", "/api/anything", nil)
	r2.AddCookie(sessCookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Code != 200 || !ok {
		t.Fatalf("session cookie: want 200, got %d (ok=%v)", rec2.Code, ok)
	}

	// 一次性 ticket → 200,再用 → 401
	ticket, err := s.tickets.issue()
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	r = httptest.NewRequest("GET", "/api/anything?ticket="+ticket, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("ticket: want 200, got %d", rec.Code)
	}
	r = httptest.NewRequest("GET", "/api/anything?ticket="+ticket, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("ticket replay: want 401, got %d", rec.Code)
	}

	// /api/auth/* 豁免
	r = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader("{}"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("/api/auth/* must be exempt: got %d", rec.Code)
	}
}

func cookieFor(tok string) *http.Cookie {
	return &http.Cookie{Name: refreshCookieName, Value: tok}
}

func TestAuthRefreshEndpoint(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}

	rt, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	r.AddCookie(cookieFor(rt))
	rec := httptest.NewRecorder()
	s.authRefresh(rec, r)
	if rec.Code != 200 {
		t.Fatalf("refresh: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["token"] == nil {
		t.Fatalf("refresh response should carry a new access token: %v %v", err, out)
	}
	// 响应同时下发旋转后的 refresh cookie
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshCookieName && c.Value != "" {
			found = true
			if !c.HttpOnly || c.Path != refreshCookiePath {
				t.Fatalf("refresh cookie attrs: HttpOnly=%v Path=%q", c.HttpOnly, c.Path)
			}
		}
	}
	if !found {
		t.Fatal("refresh must rotate the cookie")
	}
	// 旧票已作废
	if _, ok := validateRefreshToken(kv, rt, 0); ok {
		t.Fatal("old refresh token must be invalidated after rotation")
	}

	// 无 cookie → 401
	rec = httptest.NewRecorder()
	s.authRefresh(rec, httptest.NewRequest("POST", "/api/auth/refresh", nil))
	if rec.Code != 401 {
		t.Fatalf("no cookie: want 401, got %d", rec.Code)
	}
}

func TestAuthLogoutRevokes(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	rt, err := issueRefreshToken(kv, 0)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	r := httptest.NewRequest("POST", "/api/auth/logout", nil)
	r.AddCookie(cookieFor(rt))
	rec := httptest.NewRecorder()
	s.authLogout(rec, r)
	if rec.Code != 200 {
		t.Fatalf("logout: want 200, got %d", rec.Code)
	}
	if _, ok := validateRefreshToken(kv, rt, 0); ok {
		t.Fatal("logout must revoke the refresh token")
	}
	// cookie 被清
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must clear the refresh cookie")
	}
}

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}
