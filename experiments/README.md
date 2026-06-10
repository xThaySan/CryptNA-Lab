# CRYPTNA paper experiments mapping

This directory reproduces the experimental scenarios from the original CRYPTNA paper on the current lab.

## Scope

The original paper evaluates:

1. Successful end-to-end handshake
2. Failed but validly-formed SPAs
   - unknown static key
   - wrong PSK
   - replayed SPA
   - expired timestamp
3. Invalid traffic
   - random UDP datagrams
   - malformed messages
4. Load tests at fixed SPA rates
   - 10 SPA/s
   - 50 SPA/s
   - 100 SPA/s
5. Metrics
   - end-to-end latency
   - PDP throughput in SPA/s
   - PDP CPU time per SPA
   - average and median over 1000 runs

## Lab differences

The original paper used:
- Node.js client
- Node.js PDP
- Go PEP
- Go-reimplemented ESP dataplane

The current lab uses:
- Go client
- Go PDP
- Go PEP
- Linux XFRM with ESP-in-UDP NAT-T

Therefore:
- security/correctness scenarios are reproducible directly;
- performance values are implementation-specific;
- final paper figures must explicitly state that the dataplane is Linux XFRM/NAT-T, not the original Go ESP dataplane.

## Mapping

| Paper scenario | Current lab script | Status |
|---|---|---|
| Valid end-to-end handshake | scripts/test_xfrm_end_to_end.sh | implemented |
| Valid multi-client tunnel setup | scripts/test_real_multi_client.sh | implemented |
| Random UDP / malformed traffic | scripts/test_spa_invalid_packets.sh | implemented |
| Wrong PSK | scripts/test_wrong_psk_no_xfrm.sh | implemented |
| Replay < 10s | scripts/test_replay_no_extra_xfrm.sh | implemented |
| Expired timestamp | scripts/test_spa_timestamp.sh | implemented |
| Unauthorized service | scripts/test_unauthorized_no_xfrm.sh | implemented, extra vs paper |
| Service stealth | scripts/test_service_hidden.sh | implemented, extra validation |
| PDP throughput 10/50/100 SPA/s | experiments/02_pdp_load_rates.sh | TODO |
| 1000-run avg/median latency | experiments/03_latency_1000.sh | TODO |
| PDP CPU time per SPA | experiments/04_pdp_cpu_cost.sh | TODO |

## Rule

Do not add performance results to the paper until the measurement scripts:
1. run inside containers, not through repeated host-side `docker exec`;
2. export raw CSV;
3. report average, median, min, max;
4. document whether Docker overhead is included.
