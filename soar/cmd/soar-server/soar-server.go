package main

import (
	"encoding/json"
	"github.com/XiaoMi/soar/advisor"
	"github.com/XiaoMi/soar/common"
	"github.com/XiaoMi/soar/database"
	"github.com/percona/go-mysql/query"
	"io/ioutil"
	"net/http"
	"strings"
)

type SQLAdviseRequest struct {
	Schema string `json:"schema"`
	SQL string `json:"sql"`
}

type SQLAdviseResponse struct {
	SQL string `json:"sql"`
	FingerPrintId string `json:"finger_print_id"`
	FingerPrint string `json:"finger_print"`
	HeuristicSuggest map[string]advisor.Rule `json:"heuristic_suggest"`
}

func advisorHandler(w http.ResponseWriter, r *http.Request) {

	advisorRequest := SQLAdviseRequest{}
	// 读取post请求的数据
	bs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(500)
		common.Log.Error("failed to read body, err: %s", err)
		return
	}

	if err = json.Unmarshal(bs, &advisorRequest); err != nil {
		w.WriteHeader(500)
		common.Log.Error("failed to unmarshal, err: %s", err)
		return
	}

	// select * from table_a where a = 1 慢sql1 5s
	// select * from table_a where a = 2 慢sql2 6s
	// select * from table_a where a = ?
	// python通过kafka读取慢sql， 加了一些责任人之类的数据
	// 在当时的代码里面，访问这个接口，然后获取fingerprint，加入到数据中心，然后再存储到es里面
	sql := strings.TrimSpace(advisorRequest.SQL)
	heuristicSuggest := make(map[string]advisor.Rule)

	// 去除无用的备注和空格

	sql = database.RemoveSQLComments(sql)
	if sql == "" {
		common.Log.Debug("empty query or comment, sql: %s", sql)
		return
	}
	common.Log.Debug("main loop SQL: %s", sql)

	// fingerprint
	fingerprint := query.Fingerprint(sql)
	common.Log.Info("fingerprint: %s", fingerprint)
	// SQL签名
	fingerprintid := query.Id(fingerprint)

	// +++++++++++++++++++++启发式规则建议[开始]+++++++++++++++++++++++{
	q, syntaxErr := advisor.NewQuery4Audit(sql)
	if syntaxErr != nil {
		common.Log.Error("parse sql failed, err: %s", syntaxErr)
		w.WriteHeader(500)
		return
	}

	common.Log.Debug("start of heuristic advisor Query: %s", q.Query)
	for item, rule := range advisor.HeuristicRules {
		// 去除忽略的建议检查
		okFunc := (*advisor.Query4Audit).RuleOK
		if !advisor.IsIgnoreRule(item) && &rule.Func != &okFunc {
			r := rule.Func(q)
			if r.Item == item {
				heuristicSuggest[item] = r
			}
		}
	}
	common.Log.Debug("end of heuristic advisor Query: %s", q.Query)
	// +++++++++++++++++++++启发式规则建议[结束]+++++++++++++++++++++++}

	resp := SQLAdviseResponse{
		SQL:         sql,
		FingerPrintId: fingerprintid,
		FingerPrint: fingerprint,
		HeuristicSuggest: heuristicSuggest,
	}

	respBs, err := json.Marshal(resp)
	if err != nil {
		common.Log.Error("failed to marshal advise response, err: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	w.Header().Add("Content-Type", "application/json")
	w.Write(respBs)
}

func main() {
	common.Log.Info("start")

	http.HandleFunc("/api/adviser", advisorHandler)

	http.ListenAndServe(":8090", nil)
}

