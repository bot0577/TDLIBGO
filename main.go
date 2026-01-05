package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

// Config 读取 config.json
type Config struct {
	APIID    int    `mapstructure:"apiId"`
	APIHash  string `mapstructure:"apiHash"`
	DataDir  string `mapstructure:"dataDir"`
	LogFile  string `mapstructure:"logFile"`
	LogLevel int    `mapstructure:"logLevel"`
	Proxy    Proxy  `mapstructure:"proxy"`
	Listen   Listen `mapstructure:"listen"`
}

type Proxy struct {
	Enabled  bool   `mapstructure:"enabled"`
	Type     string `mapstructure:"type"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type Listen struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type accountContext struct {
	account    string
	sessionDir string
	session    string
	tgClient   *telegram.Client
	api        *tg.Client
	runCtx     context.Context
	cancel     context.CancelFunc
	authState  struct {
		sync.Mutex
		phone    string
		codeHash string
	}
}

var (
	cfg        Config
	accounts   = map[string]*accountContext{}
	accountsMu sync.Mutex
)

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if err := ensureDirs(); err != nil {
		log.Fatalf("创建目录失败: %v", err)
	}
	if err := setupLogger(); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("[req] %s %s status=%d dur=%s", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start))
	})
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.POST("/auth/start", handleAuthStart)
	r.POST("/auth/code", handleAuthCode)
	r.POST("/auth/password", handleAuthPassword)
	r.GET("/auth/state", handleAuthState) // 仅用于排查，返回当前 account 的手机号与 hash 是否存在
	r.GET("/me", handleGetMe)
	r.GET("/chats", handleListChats)
	r.GET("/accounts", handleListAccounts)
	r.POST("/account/reset", handleResetAccount)

	addr := cfg.Listen.Host + ":" + strconv.Itoa(cfg.Listen.Port)
	log.Printf("服务启动于 http://%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

func loadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	return viper.Unmarshal(&cfg)
}

func ensureDirs() error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func setupLogger() error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if cfg.LogFile == "" {
		return nil
	}
	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	return nil
}

func getOrCreateAccount(id string) (*accountContext, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("account 不能为空")
	}
	accountsMu.Lock()
	defer accountsMu.Unlock()
	if acc, ok := accounts[id]; ok {
		return acc, nil
	}

	sessionDir := filepath.Join(cfg.DataDir, id)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return nil, err
	}
	sessionPath := filepath.Join(sessionDir, "session.json")

	opts := telegram.Options{
		SessionStorage: &session.FileStorage{Path: sessionPath},
		Logger:         zap.NewExample(),
	}

	if cfg.Proxy.Enabled && cfg.Proxy.Type == "socks5" {
		proxyURL := &url.URL{Scheme: "socks5", Host: cfg.Proxy.Host + ":" + strconv.Itoa(cfg.Proxy.Port)}
		if cfg.Proxy.Username != "" {
			proxyURL.User = url.UserPassword(cfg.Proxy.Username, cfg.Proxy.Password)
		}
		d, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return nil, err
		}
		opts.Resolver = dcs.Plain(dcs.PlainOptions{
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.Dial(network, addr)
			},
		})
	}

	acc := &accountContext{
		account:    id,
		sessionDir: sessionDir,
		session:    sessionPath,
	}
	acc.tgClient = telegram.NewClient(cfg.APIID, cfg.APIHash, opts)

	ready := make(chan struct{})
	acc.runCtx, acc.cancel = context.WithCancel(context.Background())
	go func() {
		err := acc.tgClient.Run(acc.runCtx, func(ctx context.Context) error {
			acc.api = tg.NewClient(acc.tgClient)
			close(ready)
			<-ctx.Done()
			return ctx.Err()
		})
		if err != nil {
			log.Printf("账户 %s 客户端退出: %v", id, err)
		}
	}()
	<-ready
	accounts[id] = acc
	return acc, nil
}

// ---------- Handlers ----------

type phoneReq struct {
	Account string `json:"account"`
	Phone   string `json:"phone"`
}

func handleAuthStart(c *gin.Context) {
	var req phoneReq
	if err := c.BindJSON(&req); err != nil || req.Phone == "" || strings.TrimSpace(req.Account) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account、phone 必填"})
		return
	}
	phone := normalizePhone(req.Phone)
	log.Printf("[auth/start] account=%s raw_phone=%s normalized=%s", req.Account, req.Phone, phone)

	acc, err := getOrCreateAccount(req.Account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	acc.authState.Lock()
	defer acc.authState.Unlock()

	acc.authState.phone = phone
	acc.authState.codeHash = ""

	sentClass, err := acc.tgClient.Auth().SendCode(acc.runCtx, phone, auth.SendCodeOptions{})
	if err != nil {
		log.Printf("[auth/start] account=%s sendCode error=%v", req.Account, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sent, ok := sentClass.(*tg.AuthSentCode)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unexpected sent code type"})
		return
	}
	acc.authState.codeHash = sent.PhoneCodeHash
	log.Printf("[auth/start] account=%s code_hash_len=%d hash=%s", req.Account, len(sent.PhoneCodeHash), maskHash(sent.PhoneCodeHash))
	c.JSON(http.StatusOK, gin.H{"status": "code_sent"})
}

type codeReq struct {
	Account string `json:"account"`
	Code    string `json:"code"`
}

func handleAuthCode(c *gin.Context) {
	var req codeReq
	if err := c.BindJSON(&req); err != nil || req.Code == "" || strings.TrimSpace(req.Account) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account、code 必填"})
		return
	}
	code := strings.TrimSpace(req.Code)
	log.Printf("[auth/code] account=%s code=%s", req.Account, code)

	acc, err := getOrCreateAccount(req.Account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	acc.authState.Lock()
	phone := acc.authState.phone
	codeHash := acc.authState.codeHash
	acc.authState.Unlock()

	if phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先调用 /auth/start"})
		return
	}
	if codeHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码会话已失效，请重新获取验证码"})
		return
	}

	log.Printf("[auth/code] account=%s phone=%s code_hash_len=%d hash=%s", req.Account, phone, len(codeHash), maskHash(codeHash))
	// 与发送验证码时一致，直接使用规范化后的手机号（包含一个前缀 +）
		// Telegram SignIn 不接受带 "+" 的手机号，这里去掉前导 "+" 再提交
		phoneForSignIn := strings.TrimPrefix(strings.TrimSpace(phone), "+")
		log.Printf("[auth/code] debug submit => phone=%s phone_for_signin=%s codeHash(raw)=%s code=%s", phone, phoneForSignIn, codeHash, code)
	_, err = acc.tgClient.Auth().SignIn(acc.runCtx, phoneForSignIn, codeHash, code)
	if err != nil {
		if strings.Contains(err.Error(), "SESSION_PASSWORD_NEEDED") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "需要二步验证密码", "need_password": true})
			return
		}
		log.Printf("[auth/code] account=%s signin error=%v", req.Account, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	acc.authState.Lock()
	acc.authState.phone = ""
	acc.authState.codeHash = ""
	acc.authState.Unlock()
	c.JSON(http.StatusOK, gin.H{"status": "authorized"})
}

type passwordReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

func handleAuthPassword(c *gin.Context) {
	var req passwordReq
	if err := c.BindJSON(&req); err != nil || req.Password == "" || strings.TrimSpace(req.Account) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account、password 必填"})
		return
	}
	acc, err := getOrCreateAccount(req.Account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, err := acc.tgClient.Auth().Password(acc.runCtx, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	acc.authState.Lock()
	acc.authState.phone = ""
	acc.authState.codeHash = ""
	acc.authState.Unlock()
	c.JSON(http.StatusOK, gin.H{"status": "authorized"})
}

func handleAuthState(c *gin.Context) {
	account := strings.TrimSpace(c.Query("account"))
	if account == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account 必填"})
		return
	}
	acc, err := getOrCreateAccount(account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	acc.authState.Lock()
	phone := acc.authState.phone
	codeHash := acc.authState.codeHash
	acc.authState.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"phone":         phone,
		"has_codehash":  codeHash != "",
		"codehash_len":  len(codeHash),
		"codehash_dbg":  maskHash(codeHash),
		"codehash_full": codeHash,
	})
}

func handleGetMe(c *gin.Context) {
	account := strings.TrimSpace(c.Query("account"))
	if account == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account 必填"})
		return
	}
	acc, err := getOrCreateAccount(account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if acc.api == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "客户端未就绪"})
		return
	}
	me, err := acc.api.UsersGetFullUser(acc.runCtx, &tg.InputUserSelf{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, me)
}

func handleListChats(c *gin.Context) {
	account := strings.TrimSpace(c.Query("account"))
	if account == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account 必填"})
		return
	}
	acc, err := getOrCreateAccount(account)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if acc.api == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "客户端未就绪"})
		return
	}
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 50
	}
	resp, err := acc.api.MessagesGetDialogs(acc.runCtx, &tg.MessagesGetDialogsRequest{
		OffsetPeer: &tg.InputPeerEmpty{},
		Limit:      limit,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func handleListAccounts(c *gin.Context) {
	accountsMu.Lock()
	defer accountsMu.Unlock()
	list := make([]gin.H, 0, len(accounts))
	for _, acc := range accounts {
		list = append(list, gin.H{
			"account":     acc.account,
			"sessionPath": acc.session,
			"ready":       acc.api != nil,
		})
	}
	c.JSON(http.StatusOK, list)
}

func handleResetAccount(c *gin.Context) {
	var req struct {
		Account string `json:"account"`
	}
	if err := c.BindJSON(&req); err != nil || strings.TrimSpace(req.Account) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account 必填"})
		return
	}

	account := strings.TrimSpace(req.Account)
	accountsMu.Lock()
	acc, ok := accounts[account]
	if ok && acc.cancel != nil {
		acc.cancel()
	}
	delete(accounts, account)
	accountsMu.Unlock()

	// 清理 session 目录
	if acc != nil && acc.sessionDir != "" {
		if err := os.RemoveAll(acc.sessionDir); err != nil {
			log.Printf("[account/reset] 删除目录失败 account=%s err=%v", account, err)
		}
	}
	log.Printf("[account/reset] account=%s done", account)
	c.JSON(http.StatusOK, gin.H{"status": "reset", "account": account})
}

func maskHash(h string) string {
	if h == "" {
		return ""
	}
	if len(h) <= 6 {
		return h
	}
	return h[:3] + "..." + h[len(h)-3:]
}

func normalizePhone(p string) string {
	p = strings.TrimSpace(p)
	// 只保留数字，Telegram 后端接受纯数字（不带 +），避免用户多输 + 号导致格式异常
	var b strings.Builder
	for _, r := range p {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	digits := b.String()
	if digits == "" {
		return ""
	}
	return "+" + digits
}
