package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

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

type PluginOutput struct {
	Target    string      `json:"target"`
	Timestamp int64       `json:"timestamp"`
	Hops      []HopResult `json:"hops"`
	Error     string      `json:"error,omitempty"`
}

const (
	MaxHops     = 30
	ReadTimeout = 1500 * time.Millisecond
)

func main() {
	targetFlag := flag.String("target", "", "MTR Target IP or Domain")
	countFlag := flag.Int("count", 10, "Packets per hop")
	timeoutFlag := flag.Int("timeout", 45, "Max execution time")
	flag.Parse()

	if *targetFlag == "" {
		outputError("Missing target parameter")
		return
	}

	ipAddr, err := net.ResolveIPAddr("ip", *targetFlag)
	if err != nil {
		outputError(fmt.Sprintf("DNS resolution failed: %v", err))
		return
	}

	isIPv4 := ipAddr.IP.To4() != nil

	// 执行前置系统权限探测
	if err := checkRawSocketPermission(isIPv4); err != nil {
		outputError(err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutFlag)*time.Second)
	defer cancel()

	var conn *icmp.PacketConn
	var protocol int

	if isIPv4 {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		protocol = 1
	} else {
		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		protocol = 58
	}

	if err != nil {
		outputError("Failed to initialize raw socket despite permission check.")
		return
	}
	defer conn.Close()

	pid := os.Getpid() & 0xffff
	seq := 1

	output := PluginOutput{
		Target:    *targetFlag,
		Timestamp: time.Now().Unix(),
		Hops:      make([]HopResult, 0),
	}

	targetReached := false

	for ttl := 1; ttl <= MaxHops; ttl++ {
		if targetReached {
			break
		}

        if isIPv4 {
            conn.IPv4PacketConn().SetTTL(ttl)
        } else {
            conn.IPv6PacketConn().SetHopLimit(ttl)
        }

		hop := HopResult{
			Count: ttl,
			Host:  "???",
			Snt:   *countFlag,
			Best:  math.MaxFloat64,
		}

		var rtts []float64
		var recvCount int
		var currentHost string

		for i := 0; i < *countFlag; i++ {
			if ctx.Err() != nil {
				outputError("Execution global timeout")
				return
			}

			var icmpType icmp.Type = ipv4.ICMPTypeEcho
			if !isIPv4 {
				icmpType = ipv6.ICMPTypeEchoRequest
			}

			wm := icmp.Message{
				Type: icmpType, Code: 0,
				Body: &icmp.Echo{
					ID: pid, Seq: seq,
					Data: []byte("FloatMTR"),
				},
			}
			wb, _ := wm.Marshal(nil)

			start := time.Now()
			if _, err := conn.WriteTo(wb, ipAddr); err != nil {
				seq++
				continue
			}

			reply := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(ReadTimeout))
			n, peer, err := conn.ReadFrom(reply)
			rtt := time.Since(start).Seconds() * 1000

			currentSeq := seq
			seq++

			if err != nil {
				continue
			}

			rm, err := icmp.ParseMessage(protocol, reply[:n])
			if err != nil {
				continue
			}

			switch rm.Type {
			case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
				if te, ok := rm.Body.(*icmp.TimeExceeded); ok {
					if validateNestedICMP(te.Data, pid, currentSeq, isIPv4) {
						currentHost = peer.String()
						recvCount++
						rtts = append(rtts, rtt)
						hop.Last = rtt
					}
				}
			case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
				if pkt, ok := rm.Body.(*icmp.Echo); ok {
					if pkt.ID == pid && pkt.Seq == currentSeq {
						currentHost = peer.String()
						recvCount++
						rtts = append(rtts, rtt)
						hop.Last = rtt
						targetReached = true
					}
				}
			}
		}

		if currentHost != "" {
			hop.Host = currentHost
		}

		hop.Loss = float64(hop.Snt-recvCount) / float64(hop.Snt) * 100

		if recvCount > 0 {
			var sum float64
			for _, r := range rtts {
				sum += r
				if r < hop.Best {
					hop.Best = r
				}
				if r > hop.Wrst {
					hop.Wrst = r
				}
			}
			hop.Avg = sum / float64(recvCount)

			if recvCount > 1 {
				var varianceSum float64
				for _, r := range rtts {
					varianceSum += math.Pow(r-hop.Avg, 2)
				}
				hop.StDev = math.Sqrt(varianceSum / float64(recvCount-1))
			}
		} else {
			hop.Best = 0
		}

		output.Hops = append(output.Hops, hop)
	}

	finalJSON, _ := json.Marshal(output)
	fmt.Println(string(finalJSON))
}

func checkRawSocketPermission(isIPv4 bool) error {
	network := "ip4:icmp"
	if !isIPv4 {
		network = "ip6:ipv6-icmp"
	}

	conn, err := net.ListenPacket(network, "0.0.0.0")
	if err != nil {
		errStr := strings.ToLower(err.Error())

		if strings.Contains(errStr, "permission denied") ||
			strings.Contains(errStr, "socket: access denied") ||
			strings.Contains(errStr, "forbidden by its access permissions") {

			if runtime.GOOS == "windows" {
				return fmt.Errorf("系统权限拒绝: 需要以 Administrator 身份运行探针进程")
			}

			exePath, _ := os.Executable()
			exeName := filepath.Base(exePath)
			return fmt.Errorf("系统权限拒绝: 需以 Root 执行，或手动执行 'sudo setcap cap_net_raw+ep %s'", exeName)
		}
		return fmt.Errorf("无法初始化网络接口: %v", err)
	}

	conn.Close()
	return nil
}

func validateNestedICMP(data []byte, expectedID int, expectedSeq int, isIPv4 bool) bool {
	if isIPv4 {
		if len(data) < 28 {
			return false
		}
		ihl := int(data[0]&0x0f) * 4
		if len(data) < ihl+8 {
			return false
		}
		icmpData := data[ihl:]
		id := int(icmpData[4])<<8 | int(icmpData[5])
		seq := int(icmpData[6])<<8 | int(icmpData[7])
		return id == expectedID && seq == expectedSeq
	} else {
		if len(data) < 48 {
			return false
		}
		icmpData := data[40:]
		id := int(icmpData[4])<<8 | int(icmpData[5])
		seq := int(icmpData[6])<<8 | int(icmpData[7])
		return id == expectedID && seq == expectedSeq
	}
}

func outputError(msg string) {
	out := PluginOutput{
		Timestamp: time.Now().Unix(),
		Error:     msg,
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	os.Exit(1)
}