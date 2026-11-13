package main

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
)

const (
	shmPath    = "/dev/shm/aethon_stats.shm"
	numEvents  = 17
	shmMinSize = 8 * (6 + numEvents) // 6 header u64s + 17 event u64s = 184 bytes
)

// Names matching C++ aethon::stats::kEventNames in event_counters.h
var eventFieldNames = [numEvents]string{
	"tcp_bad_checksum",
	"rst_no_session",
	"rst_overlap_evasion",
	"rst_dpi_match",
	"rst_sni_blocked",
	"rst_bad_client_hello",
	"rst_backend_failed",
	"rst_tls_error",
	"ja3_rate_limited",
	"syn_cookie_sent",
	"syn_cookie_accepted",
	"session_expired_idle",
	"session_rto_give_up",
	"syn_dropped_memory_pressure",
	"session_evicted_memory_pressure",
	"icmp_pmtu_update",
	"icmp_forwarded_to_kernel",
}

// ShmRawData mirrors the packed C struct written by Aethon C++
type ShmRawData struct {
	TotalPackets   uint64
	TotalBytes     uint64
	TimestampNs    uint64
	ActiveSessions uint64
	SpeedPps       uint64
	SpeedBps       uint64
	Events         [numEvents]uint64
	XdpPackets     [5]uint64
	XdpBytes       [5]uint64
}

// StatsResponse is what is returned to the dashboard UI as JSON
type StatsResponse struct {
	RxPacketsPerSec   uint64            `json:"rx_packets_per_sec"`
	RxBytesPerSec     uint64            `json:"rx_bytes_per_sec"`
	TotalPackets      uint64            `json:"total_packets"`
	TotalBytes        uint64            `json:"total_bytes"`
	ActiveSessions    uint64            `json:"active_sessions"`
	EngineMode        int               `json:"engine_mode"`
	MemoryPressurePct float64           `json:"memory_pressure_pct"`
	Uptime            string            `json:"uptime"`
	Events            map[string]uint64 `json:"events"`
	XdpStats          map[int]XdpStat   `json:"xdp_stats"`
}
type XdpStat struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

var (
	rateMu   sync.Mutex
	prevSnap *ShmRawData
	prevTime time.Time
)

// read the /dev/shm/aethon_stats.shm

func ReadShm() *ShmRawData {
	data, err := os.ReadFile(shmPath)
	if err != nil || len(data) < shmMinSize {
		return nil
	}

	le := binary.LittleEndian
	raw := &ShmRawData{
		TotalPackets:   le.Uint64(data[0:8]),
		TotalBytes:     le.Uint64(data[8:16]),
		TimestampNs:    le.Uint64(data[16:24]),
		ActiveSessions: le.Uint64(data[24:32]),
		SpeedPps:       le.Uint64(data[32:40]),
		SpeedBps:       le.Uint64(data[40:48]),
	}
	for i := 0; i < numEvents; i++ {
		offset := 48 + i*8
		raw.Events[i] = le.Uint64(data[offset : offset+8])
	}
	if len(data) >= 8*(6+numEvents+10) {
		for act := 0; act < 5; act++ {
			pOff := 8 * (6 + numEvents + act)
			bOff := 8 * (6 + numEvents + 5 + act)
			raw.XdpPackets[act] = le.Uint64(data[pOff : pOff+8])
			raw.XdpBytes[act] = le.Uint64(data[bOff : bOff+8])
		}
	}
	return raw

}

// GetLiveStats combine shm data and computes live rates

func GetLiveStats() *StatsResponse {
	raw := ReadShm()
	if raw == nil {
		return nil
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()

	totalP := raw.TotalPackets
	totalB := raw.TotalBytes
	var xdpTotalP, xdpTotalB uint64
	for i := 0; i < 5; i++ {
		xdpTotalP += raw.XdpPackets[i]
		xdpTotalB += raw.XdpBytes[i]
	}
	if xdpTotalP > totalP {
		totalP = xdpTotalP
	}
	if xdpTotalB > totalB {
		totalB = xdpTotalB
	}

	rxPps := raw.SpeedPps
	rxBps := raw.SpeedBps

	// Fallback to delta calculation if speed wasn't written yet
	if rxPps == 0 && rxBps == 0 && prevSnap != nil && !prevTime.IsZero() {
		dt := now.Sub(prevTime).Seconds()
		if dt > 0.05 {
			if totalP >= prevSnap.TotalPackets {
				rxPps = uint64(float64(totalP-prevSnap.TotalPackets) / dt)
			}
			if totalB >= prevSnap.TotalBytes {
				rxBps = uint64(float64(totalB-prevSnap.TotalBytes) / dt)
			}
		}
	}
	prevSnap = &ShmRawData{
		TotalPackets:   totalP,
		TotalBytes:     totalB,
		TimestampNs:    raw.TimestampNs,
		ActiveSessions: raw.ActiveSessions,
		SpeedPps:       raw.SpeedPps,
		SpeedBps:       raw.SpeedBps,
		Events:         raw.Events,
		XdpPackets:     raw.XdpPackets,
		XdpBytes:       raw.XdpBytes,
	}
	prevTime = now

	eventsMap := make(map[string]uint64, numEvents)
	for i, name := range eventFieldNames {
		eventsMap[name] = raw.Events[i]
	}
	xdpMap := make(map[int]XdpStat, 5)
	for i := 0; i < 5; i++ {
		xdpMap[i] = XdpStat{
			Packets: raw.XdpPackets[i],
			Bytes:   raw.XdpBytes[i],
		}
	}
	return &StatsResponse{
		RxPacketsPerSec:   rxPps,
		RxBytesPerSec:     rxBps,
		TotalPackets:      totalP,
		TotalBytes:        totalB,
		ActiveSessions:    raw.ActiveSessions,
		EngineMode:        getEngineMode(),
		MemoryPressurePct: 0.0,
		Uptime:            "online",
		Events:            eventsMap,
		XdpStats:          xdpMap,
	}
}
