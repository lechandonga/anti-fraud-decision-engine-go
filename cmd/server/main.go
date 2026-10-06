// 本地反欺诈风险判定与告警服务入口。
//
// 启动：go run ./cmd/server （默认 :8080，可用 ADDR 环境变量覆盖）
// 内存存储、无外部服务依赖；启动时自动发布演示规则集 v1。
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/engine"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/server"
)

func demoRuleSetV1() *rules.RuleSet {
	return &rules.RuleSet{
		SchemaVersion: rules.SchemaVersion,
		Version:       "v1",
		Description:   "初始演示规则集：大额、高频、黑白名单",
		Rules: []rules.Rule{
			{
				ID: "amount-large", Name: "大额交易", Kind: rules.KindAmount,
				Enabled: true, RiskLevel: model.RiskHigh, MinAmount: 50000,
			},
			{
				ID: "freq-5m-3", Name: "5分钟内3笔", Kind: rules.KindFrequency,
				Enabled: true, RiskLevel: model.RiskMedium,
				Window: 5 * time.Minute, Threshold: 3,
			},
			{
				ID: "list-black-account", Name: "黑名单账户", Kind: rules.KindList,
				Enabled: true, RiskLevel: model.RiskCritical,
				ListType: "black", MatchOn: []string{"account", "counterparty"},
			},
			{
				ID: "list-white", Name: "白名单豁免", Kind: rules.KindList,
				Enabled: true, RiskLevel: model.RiskLow,
				ListType: "white", MatchOn: []string{"account"},
			},
		},
		Lists: []rules.List{
			{Name: "global-black", Type: "black", Entries: []string{"ACCT-FRAUD-001", "CP-DARK-001"}},
			{Name: "vip-white", Type: "white", Entries: []string{"ACCT-VIP-001"}},
		},
	}
}

func main() {
	store := rules.NewStore()
	if err := store.Publish(demoRuleSetV1()); err != nil {
		log.Fatalf("发布初始规则集失败: %v", err)
	}
	alerts := alert.NewService(time.Now)
	eng := engine.New(store, alerts, engine.DefaultConfig(), time.Now)
	srv := server.New(eng, store)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("反欺诈判定服务已启动，监听 %s（当前规则集 v1，hash=%s）", addr, mustCurrentHash(store))
	log.Fatal(http.ListenAndServe(addr, srv.Mux))
}

func mustCurrentHash(store *rules.Store) string {
	rs, err := store.Current()
	if err != nil {
		return ""
	}
	return rs.Hash()
}
