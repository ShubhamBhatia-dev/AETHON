# Aethon — road to production

What stands between the current state (passes an end-to-end + torture suite on veth, in generic
XDP mode, on a laptop) and something you can trust in front of real traffic on a VPS.

Legend: **[P0]** must-have before any real deployment · **[P1]** needed for a dependable VPS ·
**[P2]** performance / completeness · **[P3]** operations & polish.

---

## P0 — Safety before it ever faces real traffic

- [ ] **Fail-open on crash.** If `afxdp_control` dies, XDP keeps redirecting to a dead socket and
      the site goes dark. Ship a systemd unit with `Restart=always` and
      `ExecStopPost=/sbin/ip link set dev <iface> xdp off`, plus a watchdog. Verify: `kill -9`
      the process and confirm traffic still flows through the kernel.
- [ ] **Global memory budget.** Per-session buffers are capped, but nothing bounds *total* memory.
      A slow-read / many-connection attack can still OOM the host. Add a per-worker byte budget
      (≈ 40% RAM / workers); when exceeded: advertise zero window, stop reading backends, refuse
      new SYNs, evict oldest idle sessions. Test with `slowhttptest` while watching RSS.
- [ ] **Deploy in monitor-only mode first.** A config switch to log what *would* be blocked
      without resetting connections, so a false-positive rule can't take the site down on day one.
- [ ] **Bind backends to 127.0.0.1 and document it.** If a backend listens on 0.0.0.0 clients can
      reach it directly and bypass Aethon. The test suite already checks this; make it a hard
      requirement in the docs and sample configs.

## P1 — Correctness & hardening for a dependable VPS

- [ ] **TCP retransmission edge cases under real loss.** Retransmit queue, RTO and fast-retransmit
      exist; validate SACK-less recovery over `tc netem loss 10% reorder` on a *real* NIC, not just
      veth. Add a soak test (hours) and watch the `[Events]` counters.
- [ ] **ICMP to the kernel.** Currently only echo is handled in userspace; other ICMP types are
      dropped, which breaks path-MTU discovery. Pass all ICMP via `XDP_PASS` (or handle PMTU).
- [ ] **TLS handshakes off the packet thread.** A handshake does ~1 ms of asymmetric crypto on the
      worker; a ClientHello flood stalls the queue. Move handshakes to a small worker pool or add a
      per-IP handshake rate limit. (SYN cookies and JA3 limiting already exist as first lines.)
- [ ] **Certificate & config reload without downtime.** Reload `services.conf`, `blocked_domains`,
      rules and certs on `SIGHUP` instead of a restart that drops every connection. Add ACME/
      Let's Encrypt renewal handling.
- [ ] **Stronger ISN / SYN-cookie secret rotation.** SipHash keys are random at startup; rotate the
      cookie secret on a timer and keep the previous one valid for one window.
- [ ] **IPv6.** Today IPv6 is passed to the kernel uninspected. Either document it as out of scope
      clearly, or add an IPv6 path (duplicate the IPv4 parse/reassembly with 128-bit addresses).

## P2 — Performance & protocol completeness

- [ ] **Window scaling + SACK.** Capped at 64 KB in flight today, so throughput collapses on
      long-RTT or lossy links. Negotiate window scale in the SYN-ACK (options already parsed) and
      implement SACK for fast loss recovery.
- [ ] **Native-mode zero-copy on a real NIC.** Currently generic XDP + copy mode. Get
      `XDP_MODE_NATIVE` + `XDP_ZEROCOPY` working on real hardware (ena/ixgbe/i40e/mlx5) and keep the
      README's claims conditional on what actually succeeds.
- [ ] **Benchmarks with a methodology.** p50/p99/p99.9 latency and packets/s per core, measured
      with `wrk2`/`TRex` against baselines (nginx alone, Suricata+nginx). Publish hardware, kernel,
      driver, commands and raw data under `benchmarks/`. This is the single highest-value item for
      credibility.
- [ ] **Backend connection pooling / keep-alive to the backend.** One loopback socket per client
      session is fine for a VPS but wasteful; pool/keep-alive reduces syscalls and latency.
- [ ] **Replace `vector::erase`-from-front on the hot path** (send/backend buffers) with a ring or
      head offset to avoid O(n) shifts under load.
- [ ] **Multi-queue flow stability.** Sessions are per-worker and rely on RSS keeping a flow on one
      queue. Document the requirement (the test disables TX re-hashing) and detect/РASS when the NIC
      can't guarantee it.

## P3 — Operations, observability, maintenance

- [ ] **Async, rate-limited logging via FluxIO.** Move `std::cout`/alerts off the packet thread
      onto per-worker SPSC rings drained by a logger thread; rate-limit and aggregate so an attack
      can't flood logs. (Fix FluxIO's `flush_stream` page-reuse bug first.)
- [ ] **Metrics endpoint.** Export the `[Events]` counters, session count, pps/bps and memory as
      Prometheus metrics so the VPS can be monitored and alerted.
- [ ] **Log rotation.** Size-based rotation or `logrotate`/`SIGHUP` reopen so logs don't fill the
      disk.
- [ ] **Drop privileges after setup.** Start with only `CAP_NET_ADMIN` + `CAP_BPF`, drop the rest,
      add a seccomp profile.
- [ ] **Fuzzing + sanitizers in CI.** libFuzzer/AFL++ on the parsers (IP/TCP options, TLS
      ClientHello, rule parser); run the offline tests under ASan/UBSan/TSan in GitHub Actions.
- [ ] **CI pipeline.** Build + `tests/run_all.sh --offline` on every push; a self-hosted runner for
      the root-level e2e/torture suite.
- [ ] **Packaging.** A `.deb`/container plus an install guide, so it can be deployed and upgraded
      cleanly.
- [ ] **Real-world soak.** Run it in front of algomesh.in in monitor-only mode for a few weeks,
      then enable blocking. Production trust is earned by uptime, not by tests. Write up what broke.

---

## Known limitations to clear (from README)

- [ ] IPv4 only (IPv6 passed through).
- [ ] No window scaling / SACK → slow on long, lossy paths.
- [ ] TLS handshakes and logging run on the packet threads.
- [ ] JA3 rate limiting is per-worker and per-fingerprint (coarse; all clients of one TLS library
      share a fingerprint).
- [ ] XDP rate limiter and IP blocklist are implemented but disabled in the BPF program.

## Done (for reference)

Handshake + reassembly + overlap-evasion detection; flow control both directions; RFC 6298 RTO;
Reno congestion control + fast retransmit; go-back-N; graceful/half close + FIN retransmit; random
ISN; SYN cookies; TCP checksum verification; TLS termination + SNI policy; split-ClientHello
reassembly; JA3 per-worker rate limiting; Hyperscan streaming DPI with full Suricata rule sets
(policy-based, compiled-DB cache); per-reason event counters; malloc_trim + RELEASE_BUFFERS;
offline unit/fuzz/DPI/JA3 tests and a root-level e2e + torture suite (`tests/run_all.sh`).
