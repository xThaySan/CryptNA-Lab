# CRYPTNA Lab Experimental Results

This document summarizes the experimental results obtained on the current CRYPTNA lab.

## Context

The current lab validates a CRYPTNA-like architecture with:

- SPA based on Noise IKpsk1
- PDP-side client authentication
- PIP-based client metadata and PSK lookup
- PEP activation after successful authorization
- Linux XFRM with ESP-in-UDP NAT-T
- service isolation behind the PEP
- multi-client support

Important methodological note:

The original CRYPTNA paper used a different implementation stack. The current lab uses Go components and Linux XFRM/NAT-T. Therefore, the results are functionally comparable, but raw timings must not be presented as an exact reproduction of the original implementation.

---

## 1. Correctness matrix

Command:

```bash
./experiments/01_correctness_matrix.sh
```

Result:

| Scenario | Status |
|---|---:|
| Network isolation | PASS |
| Invalid random and malformed SPA | PASS |
| Expired timestamp | PASS |
| Replay cache | PASS |
| Wrong PSK, no XFRM | PASS |
| Unauthorized service, no XFRM | PASS |
| Successful XFRM NAT-T end-to-end | PASS |
| Real multi-client XFRM NAT-T | PASS |

Conclusion:

The lab correctly enforces the expected CRYPTNA security properties. Invalid, replayed, expired, unauthorized, and wrong-PSK requests do not activate access. Valid clients obtain an XFRM NAT-T tunnel. Multiple clients can be authorized concurrently with distinct sessions.

---

## 2. Sequential control-plane handshake latency

Command:

```bash
./experiments/02_handshake_latency_1000.sh
```

Mode:

- `XFRM_MODE=dry-run`
- 1000 sequential valid handshakes
- measured from inside the client container
- includes SPA creation, PDP validation, PIP lookup, PEP activation, encrypted response, and client-side processing
- excludes real kernel XFRM application

Result:

| Runs | OK | Failed | Avg ms | Median ms | Min ms | Max ms | P95 ms |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1000 | 1000 | 0 | 4.542 | 3.979 | 2.825 | 39.485 | 7.693 |

Conclusion:

The control-plane handshake is stable over 1000 sequential runs, with no failure. The average latency is below 5 ms in dry-run mode.

---

## 3. Open-loop valid SPA load test

Command:

```bash
N=100 RATES="10 50 100" ./experiments/03_pdp_load_rates.sh
```

Scenario:

- valid SPA
- open-loop generation
- dry-run XFRM
- client-side end-to-end measurement

Result:

| Scenario | Target SPA/s | Runs | OK | Failed | Achieved SPA/s | Avg ms | Median ms | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| valid | 10 | 100 | 100 | 0 | 10.091 | 8.537 | 8.527 | 9.645 |
| valid | 50 | 100 | 100 | 0 | 50.278 | 7.963 | 7.936 | 8.689 |
| valid | 100 | 100 | 100 | 0 | 100.194 | 7.723 | 7.693 | 8.403 |

Conclusion:

The lab sustains 10, 50, and 100 valid SPA/s without failures. At these rates, the client-side observed latency remains stable, around 8 ms.

---

## 4. Open-loop load test: valid, wrong PSK, random

Command:

```bash
N=100 RATES="10 50 100" ./experiments/03_pdp_load_rates.sh
```

Important note:

For `wrong-psk` and `random`, the client expects no response from the PDP. Therefore, the observed client-side duration is dominated by the configured no-response timeout. These values validate drop behavior and rate handling, but they are not PDP processing latency values.

Result:

| Scenario | Target SPA/s | Runs | OK | Failed | Achieved SPA/s | Avg ms | Median ms | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| valid | 10 | 100 | 100 | 0 | 10.091 | 8.537 | 8.527 | 9.645 |
| valid | 50 | 100 | 100 | 0 | 50.278 | 7.963 | 7.936 | 8.689 |
| valid | 100 | 100 | 100 | 0 | 100.194 | 7.723 | 7.693 | 8.403 |
| wrong-psk | 10 | 100 | 100 | 0 | 9.998 | 101.393 | 101.339 | 102.300 |
| wrong-psk | 50 | 100 | 100 | 0 | 48.020 | 101.225 | 101.148 | 101.944 |
| wrong-psk | 100 | 100 | 100 | 0 | 91.648 | 101.270 | 101.118 | 102.106 |
| random | 10 | 100 | 100 | 0 | 9.999 | 101.075 | 101.019 | 101.773 |
| random | 50 | 100 | 100 | 0 | 48.046 | 100.997 | 100.806 | 101.897 |
| random | 100 | 100 | 100 | 0 | 91.527 | 101.040 | 101.035 | 101.673 |

Conclusion:

The PDP silently drops wrong-PSK and random traffic as expected. The client-side duration around 100 ms corresponds to the no-response timeout, not the PDP processing time.

---

## 5. PDP internal processing time

Command:

```bash
N=100 RATES="10 50 100" ./experiments/04_pdp_internal_processing_rates.sh
```

Mode:

- measured inside the PDP
- based on PDP-side instrumentation
- excludes client-side response timeout
- includes the internal PDP path for each scenario

Result:

| Scenario | Target SPA/s | Events | Expected outcome count | Achieved SPA/s | Avg ms | Median ms | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| valid | 10 | 100 | 100 | 10.094 | 7.352 | 7.348 | 7.962 |
| valid | 50 | 100 | 100 | 50.327 | 6.887 | 6.835 | 7.539 |
| valid | 100 | 100 | 100 | 100.287 | 6.917 | 6.880 | 7.499 |
| wrong-psk | 10 | 100 | 100 | 10.099 | 0.612 | 0.603 | 0.739 |
| wrong-psk | 50 | 100 | 100 | 50.513 | 0.508 | 0.492 | 0.627 |
| wrong-psk | 100 | 100 | 100 | 100.827 | 0.761 | 0.734 | 1.156 |
| random | 10 | 100 | 100 | 10.102 | 0.077 | 0.071 | 0.112 |
| random | 50 | 100 | 100 | 50.510 | 0.070 | 0.063 | 0.111 |
| random | 100 | 100 | 100 | 100.948 | 0.071 | 0.062 | 0.136 |

Conclusion:

The PDP sustains 10, 50, and 100 SPA/s for all scenarios without failure.

The processing hierarchy is clear:

| Scenario | Interpretation |
|---|---|
| valid | most expensive path: Noise header, PIP lookup, payload decrypt, policy check, PEP activation, response |
| wrong-psk | intermediate path: Noise header and PIP lookup succeed, payload authentication fails |
| random | cheapest path: invalid header rejected before PIP and PEP |

---

## 6. PDP CPU cost

Command:

```bash
N=100 RATES="10 50 100" ./experiments/05_pdp_cpu_cost.sh
```

Metric:

- CPU time is read from the PDP container cgroup
- CPU cost is computed as CPU delta divided by number of PDP events
- this measures PDP CPU consumption, not wall-clock latency

Result:

| Scenario | Target SPA/s | Events | CPU ms / SPA | PDP CPU % | Avg processing ms | Median processing ms | P95 processing ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| valid | 10 | 100 | 1.050 | 1.053 | 7.402 | 7.324 | 8.118 |
| valid | 50 | 100 | 0.964 | 4.689 | 7.086 | 7.068 | 7.579 |
| valid | 100 | 100 | 0.891 | 8.413 | 6.855 | 6.836 | 7.389 |
| wrong-psk | 10 | 100 | 0.735 | 0.730 | 0.645 | 0.627 | 0.801 |
| wrong-psk | 50 | 100 | 0.649 | 3.022 | 0.527 | 0.523 | 0.632 |
| wrong-psk | 100 | 100 | 0.633 | 5.470 | 0.506 | 0.492 | 0.602 |
| random | 10 | 100 | 0.399 | 0.397 | 0.077 | 0.071 | 0.120 |
| random | 50 | 100 | 0.385 | 1.794 | 0.070 | 0.063 | 0.111 |
| random | 100 | 100 | 0.359 | 3.095 | 0.069 | 0.062 | 0.116 |

Conclusion:

The CPU cost remains low:

| Scenario | CPU cost |
|---|---:|
| valid | below 1.1 ms CPU per SPA |
| wrong-psk | below 0.75 ms CPU per SPA |
| random | below 0.40 ms CPU per datagram |

The valid path has higher wall-clock processing time than CPU time. This indicates that the valid path is dominated by control-plane interactions and scheduling, especially PIP lookup and PEP activation, rather than pure CPU computation.

---

## 7. Comparison with the original CRYPTNA paper

The original paper reports approximately:

| Scenario | Paper avg / median latency | Paper throughput |
|---|---:|---:|
| Successful SPA | 2.57 / 2.55 ms | 389 / 391 op/s |
| Wrong PSK | 2.55 / 2.54 ms | 392 / 393 op/s |
| Random message | 1.32 / 1.30 ms | 756 / 765 op/s |

The current lab reports:

| Scenario | PDP internal avg | PDP CPU cost |
|---|---:|---:|
| valid | around 6.9-7.4 ms | around 0.9-1.1 ms CPU / SPA |
| wrong-psk | around 0.5-0.8 ms | around 0.6-0.7 ms CPU / SPA |
| random | around 0.07 ms | around 0.36-0.40 ms CPU / datagram |

Interpretation:

The trends are consistent with the original paper:

- valid requests are the most expensive;
- random datagrams are rejected fastest;
- wrong-PSK requests are cheaper than valid requests because they do not activate the PEP.

However, the raw values are not directly equivalent because:

- the implementation stack is different;
- the current lab uses Go and Linux XFRM/NAT-T;
- the valid path includes PIP and PEP HTTP interactions;
- the CPU metric is container cgroup CPU time, not the same metric as protocol latency.

Therefore, these results should be presented as a reproduction of the evaluation logic, not as a strict numerical reproduction of the original prototype.

---

## 8. Summary

The current CRYPTNA lab validates:

- service hiding before authorization;
- silent drop of invalid traffic;
- replay rejection;
- expired timestamp rejection;
- wrong-PSK rejection;
- no XFRM activation for unauthorized clients;
- successful XFRM NAT-T tunnel setup for authorized clients;
- concurrent multi-client tunnel setup;
- stable operation at 10, 50, and 100 SPA/s;
- low PDP CPU cost, especially for rejected traffic.

The lab is ready for use as the experimental base for the CRYPTNA reproduction and extension work.
