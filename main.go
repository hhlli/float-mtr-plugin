package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// 标准化输出的单跳结构
type HopResult struct {
	Count int     `json:"count"`
	Host  string  `json:"host"`
	Loss  float64 `json:"loss"`
	Snt   int     `json:"snt"`
	Last  float64 `json:"last"`
	Avg   float64 `json:"avg"`
	Best  float64 `json:"best"`
	Wrst  float64 `json:"wrst"`
	StDev float64 `json:"stdev"`
}

// 插件最终输出的标准结构
type PluginOutput struct {
	Target    string      `json:"target"`
	Timestamp int64       `json:"timestamp"`
	Hops      []HopResult `json:"hops"`
	Error     string      `json:"error,omitempty"`
}

func main() {
	target := flag.String("target", "", "MTR 探测目标 IP 或域名")
	count := flag.Int("count", 10, "每跳发送的探测包数量")
	timeout := flag.Int("timeout", 60, "最大执行超时时间(秒)")
	flag.Parse()

	if *target == "" {
		outputError("Missing required parameter: -target")
		return
	}

	// 检查系统是否安装了 mtr
	mtrPath, err := exec.LookPath("mtr")
	if err != nil {
		outputError("System 'mtr' command not found. Please install mtr first.")
		return
	}

	// 设置严格的上下文超时，防止僵尸进程耗尽宿主机资源
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	// 执行 mtr，-j 输出 JSON，-n 不解析域名（提高速度），-c 指定发包数
	cmd := exec.CommandContext(ctx, mtrPath, "-j", "-n", "-c", fmt.Sprintf("%d", *count), *target)
	
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		outputError("Execution timeout: MTR process exceeded the time limit")
		return
	}
	if err != nil {
		outputError(fmt.Sprintf("MTR execution failed: %v, stderr: %s", err, stderr.String()))
		return
	}

	// 解析系统 mtr 的原生 JSON 输出
	var rawMtr map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &rawMtr); err != nil {
		outputError("Failed to parse MTR native JSON output")
		return
	}

	// 提取并标准化路由跳数数据
	standardOutput := PluginOutput{
		Target:    *target,
		Timestamp: time.Now().Unix(),
		Hops:      make([]HopResult, 0),
	}

	if report, ok := rawMtr["report"].(map[string]interface{}); ok {
		if hubs, ok := report["hubs"].([]interface{}); ok {
			for _, h := range hubs {
				if hub, ok := h.(map[string]interface{}); ok {
					hop := HopResult{
						Count: getInt(hub, "count"),
						Host:  getString(hub, "host"),
						Loss:  getFloat(hub, "Loss%"),
						Snt:   getInt(hub, "Snt"),
						Last:  getFloat(hub, "Last"),
						Avg:   getFloat(hub, "Avg"),
						Best:  getFloat(hub, "Best"),
						Wrst:  getFloat(hub, "Wrst"),
						StDev: getFloat(hub, "StDev"),
					}
					standardOutput.Hops = append(standardOutput.Hops, hop)
				}
			}
		}
	}

	// 序列化并直接输出到 Stdout 供主探针读取
	finalJSON, _ := json.Marshal(standardOutput)
	fmt.Println(string(finalJSON))
}

// --- 辅助提取函数（规避系统级 MTR 不同版本输出类型不一致的问题） ---

func outputError(msg string) {
	out := PluginOutput{
		Timestamp: time.Now().Unix(),
		Error:     msg,
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	os.Exit(1)
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		}
	}
	return 0
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		}
	}
	return 0
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}