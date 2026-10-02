# HOPCHECK — Finding Where a Network Path Becomes Slow

A Computer Networks mini-project (3rd-year CSE) that finds **where** a network
path becomes slow, instead of only measuring *whether* the destination is
reachable.

---

## 1. Project Title

**HopCheck — Finding Where a Network Path Becomes Slow**

---

## 2. Problem Statement

The two tools every student already knows answer only half of the question:

| Tool | What it answers | What it misses |
|------|-----------------|----------------|
| `ping` | Is the destination reachable? What is the total round-trip time? | It cannot tell you *where* along the path the delay is added. |
| `tracert` / `traceroute` | Which routers are traversed? | It shows one RTT sample per hop; it does not tell you whether a high RTT is real degradation or just a router answering slowly. |

So when a call to a game server or a remote file share feels laggy, `ping` says
"54 ms" and `tracert` shows a list of hops — but neither tool answers the
question we actually care about:

> **"At approximately which point along the network path does persistent
> latency increase appear?"**

A naive answer ("the hop with the highest RTT is the slow hop") is
**technically wrong**, because an intermediate router may be rate-limiting or
delaying its ICMP responses while forwarding your real traffic perfectly
fine. HopCheck therefore refuses to flag a hop on a single sample; it requires
the elevated latency to **persist** into the following hops.

---

## 3. Objective

1. Discover the network path to a destination using **TTL-based probing**
   (the traceroute principle) in a way that works on Windows.
2. Probe every discovered hop **multiple times** and compute RTT statistics
   (min / avg / max) and **packet loss**.
3. Compare the latency of each hop against the previous responding hop.
4. Classify every hop: `NORMAL`, `POSSIBLE DELAY`, `PERSISTENT SLOWDOWN`,
   `TIMEOUT`, `DESTINATION`.
5. Print a short, human-readable diagnosis in the terminal, including an
   explicit false-positive warning when a latency spike is *not* followed by
   elevated later hops.

---

## 4. How HopCheck Works

```
  Destination typed by user
            |
            v
  (1) ROUTE DISCOVERY  -- send ICMP Echo with TTL = 1, 2, 3 ... max_hops
            |             every router along the path decrements the TTL;
            |             when it hits 0 the router returns "TTL exceeded"
            v
  (2) MULTIPLE PROBES  -- for each responding hop, send `probes` echo
            |             requests and record each RTT individually
            v
  (3) STATISTICS       -- sent, received, loss %, min / avg / max RTT
            |
            v
  (4) ANALYSIS         -- compare hop N with hop N-1; if the jump is large,
            |             check whether hops N+1... stay elevated (persistence)
            v
  (5) REPORT           -- table + diagnosis in the terminal
```

Everything runs locally in the terminal. No server, no database, no GUI,
no cloud service, no Docker, no machine learning.

---

## 5. Networking Concepts Used

| Concept | Where it is used |
|---------|------------------|
| **IP routing** | The probe packet is forwarded hop-by-hop by routers until the destination is reached. Each hop is a different IP address. |
| **TTL (Time To Live)** | The TTL field of the IPv4 header is set by us to `hop_number`. Each router decrements it by 1 before forwarding. |
| **TTL exceeded / ICMP Time Exceeded** | When a router decrements TTL to 0 it must discard the packet and return an ICMP *Time Exceeded* message. The source address of that message reveals the router — this is how the path is discovered. |
| **ICMP Echo Request / Echo Reply** | The payload used to measure RTT. `ping` and HopCheck both rely on ICMP type 8 / type 0. |
| **RTT (Round Trip Time)** | `RTT = t_reply_received - t_request_sent`. Each probe is timed individually with `time.perf_counter()`. |
| **Packet loss** | `loss% = (sent - received) / sent * 100`. A hop that drops ICMP but forwards data produces `* * *` — we must not treat that as a broken path. |
| **Traceroute principle** | Increment TTL one at a time to enumerate the path; identical to `tracert` in behaviour. |
| **Latency accumulation** | Path latency is the sum of per-link delays, so the RTT to hop N is roughly the running cost of the path up to N. A jump between hop N-1 and N marks a new slow segment. |
| **ICMP de-prioritisation / rate limiting** | The reason a single high RTT is *not* proof of degradation; handled explicitly in the false-positive rule. |

---

## 6. Algorithm

### 6.1 Per-hop statistics (Phase 3)

For each responding hop, after `p` probes:

```
sent     = p
received = number of replies
loss%    = (sent - received) / sent * 100
min/avg/max RTT  -- over the successful replies only
```

Timeouts are recorded but do not contribute an RTT value.

### 6.2 Classification thresholds (Phase 4)

All thresholds are configurable constants in `analyzer.py`:

| Name | Default | Meaning |
|------|---------|---------|
| `DELTA_THRESHOLD_MS` | 20 ms | Minimum RTT jump over the previous hop that counts as "a significant increase" |
| `RATIO_THRESHOLD` | 2.0 | Jump must also be this many times the previous hop's average (guards against flagging 1 ms -> 5 ms) |
| `PERSISTENCE_HOPS` | 2 | How many following hops must stay elevated to call it persistent |
| `PERSISTENCE_TOLERANCE` | 0.75 | A later hop counts as "still elevated" if it is at least 75 % of the peak RTT seen from the candidate hop onward |
| `HIGH_LOSS_PERCENT` | 50 % | Loss at or above this is reported as significant |
| `BASE_RTT_FLOOR_MS` | 5 ms | Ignore trivial absolute increases below this floor |

Possible classifications, one per hop:

`NORMAL`, `POSSIBLE DELAY`, `PERSISTENT SLOWDOWN`, `TIMEOUT`, `DESTINATION`.

Overall assessments:

| Assessment | When |
|------------|------|
| `POSSIBLE PATH DEGRADATION` | A hop shows a large jump **and** the following hops stay elevated, so a real slow segment is identified. |
| `INCREASED PATH LATENCY, SLOW HOP NOT IDENTIFIED` | End-to-end time grew, but only across hops that never answered, so no router can be blamed. |
| `NO PERSISTENT SLOWDOWN DETECTED` | No persistent elevation; any spike was temporary or a silent-hop artefact. |
| `NO RESPONDING HOPS FOUND` | Nothing on the path answered, so no comparison is possible. |

### 6.3 The persistence test (the important rule)

For each responding hop `i > 1`:

```
increase = avg[i] - avg[i-1]

if increase < DELTA_THRESHOLD_MS          -> NORMAL
elif increase < BASE_RTT_FLOOR_MS          -> NORMAL
elif avg[i] / avg[i-1] < RATIO_THRESHOLD   -> NORMAL   (too small relatively)
else:
    # a real jump happened; is it still there later?
    elevated_after = how many of the next PERSISTENCE_HOPS hops
                     have avg >= PERSISTENCE_TOLERANCE * avg[i]

    if elevated_after >= PERSISTENCE_HOPS -> PERSISTENT SLOWDOWN  (flag it)
    else                                 -> POSSIBLE DELAY        (watch it)
```

And the **false-positive** case, which is tested explicitly:

```
5, 10, 100, 12, 15
        ^        ^^
        |        subsequent hops return to normal latency
        single-hump spike: delayed ICMP response, NOT path degradation
```

If the peak is not sustained by the following hops, the program prints a
"TEMPORARY / ICMP RESPONSE ANOMALY" note and **never** labels that hop a
confirmed slowdown.

### 6.4 Why "highest RTT = slow hop" is wrong

```
Hop 1 =  5 ms
Hop 2 = 10 ms
Hop 3 =100 ms   <-- highest single RTT, but...
Hop 4 = 12 ms
Hop 5 = 15 ms
```

If forwarding inside router 3 were genuinely slow, hops 4 and 5 could not be
faster than hop 3 — the packets still have to pass through it. So the spike is
attributed to the *router's ICMP responder*, not to the data path. Compare with
the genuine case:

```
Hop 1 =  5 ms
Hop 2 = 10 ms
Hop 3 = 50 ms
Hop 4 = 55 ms   <-- still high
Hop 5 = 58 ms   <-- still high   => degradation really began at Hop 3
```

---

## 7. Installation

Requirements:

* Windows 10 or Windows 11
* Python 3.8 or newer, with Python added to `PATH`
* No administrator privileges required
* No third-party packages

Check Python:

```powershell
python --version
```

Clone or copy the `hopcheck` folder anywhere, then (optional, and it does
nothing because there are no dependencies):

```powershell
python -m pip install -r requirements.txt
```

That is the entire installation.

---

## 8. How to Run

Open the folder in VS Code and use the integrated terminal:

```powershell
cd hopcheck
python hopcheck.py
```

You will be prompted for:

```
Enter destination: google.com
Enter probes per hop [5]: 5
Enter maximum hops [15]: 15
```

Press Enter to accept the default in brackets. All three inputs are validated;
invalid input is rejected with a clear message and re-prompted.

To exit at any time, press `Ctrl+C`.

---

## 9. Example Output

A real captured run on a Windows 11 host whose ISP edge drops ICMP for every
transit hop (`instagram.com`, 5 probes, 15 hops):

```
============================================================
                          HOPCHECK
         Finding Where a Network Path Becomes Slow
============================================================

Enter destination: instagram.com
Enter probes per hop [5]:
Enter maximum hops [15]:

Destination     : instagram.com
Resolved IP     : 163.70.146.174
Probe Count     : 5
Maximum Hop     : 15
Probe Timeout   : 1.0 s

Tracing and measuring route (up to 45 seconds)...

  1   10.65.17.72        4.2 ms
  2   192.0.0.1          6.3 ms
  3   *  Request timed out.
  ...
  15  163.70.146.174    94.0 ms

ROUTE AND MEASUREMENTS
------------------------------------------------------------
Hop  IP Address          Min      Avg     Max   Loss  Status
-------------------------------------------------------------------------
1    10.65.17.72         2.0      4.2     6.0     0%  NORMAL
2    192.0.0.1           6.3    6.3 *     6.3   100%  NORMAL
3    *                     -        -       -   100%  TIMEOUT
  ...
15   163.70.146.174     87.0     94.0   101.0     0%  DESTINATION

*  RTT from tracert, not echo probes (see Analysis)

ANALYSIS
------------------------------------------------------------

Latency increase detected at the destination (Hop 15).

Previous average RTT  : 6.3 ms  (Hop 2)
Hop 15 average RTT    : 94.0 ms
Increase              : +87.7 ms

The delay was added somewhere between Hop 2 and Hop 15,
but the hops in between never answered, so the exact point
where it was added cannot be determined from this run.

Hops 3-14 did not respond to any probe (12 hops).
Routers commonly de-prioritise ICMP, so this does not by itself
mean the path is broken: Hop 15 still answers.

Assessment: INCREASED PATH LATENCY, SLOW HOP NOT IDENTIFIED

Note: intermediate routers may rate-limit or delay ICMP replies, so a high RTT
at one hop alone is not sufficient evidence of network slowdown.

============================================================
```

Note the two honesty details in that output: hop 2 carries 100 % loss yet is
still `NORMAL` (because hop 15 answers, so the path is not broken), and its RTT
is flagged `*` because it is a single `tracert` sample rather than five measured
probes.

### Simulated path showing a real slowdown

The following is a **synthetic** trace (not captured from a network) used to
illustrate the `POSSIBLE PATH DEGRADATION` verdict, which the network above cannot
produce because every transit hop is invisible:

```
ANALYSIS
------------------------------------------------------------

Potential persistent latency increase detected around Hop 4.

Previous average RTT  : 12.4 ms  (Hop 3)
Hop 4 average RTT     : 47.9 ms
Increase              : +35.5 ms

Subsequent hops remained elevated (5, 6).

Assessment: POSSIBLE PATH DEGRADATION

Note: intermediate routers may rate-limit or delay ICMP replies, so a high RTT
at one hop alone is not sufficient evidence of network slowdown.

============================================================
```

### False-positive example

For the sequence `5, 10, 100, 12, 15` the ANALYSIS section reads:

```
Hop 3 shows an unusually high response time, but subsequent hops return to
normal latency.

Previous average RTT  : 10.0 ms  (Hop 2)
Hop 3 average RTT     : 100.0 ms
Increase              : +90.0 ms

This may indicate delayed or rate-limited ICMP responses by that
router rather than actual path degradation.

Assessment: NO PERSISTENT SLOWDOWN DETECTED
```

### Silent-hop example

```
Hops 3-11 did not respond to any probe (9 hops).
Routers commonly de-prioritise ICMP, so this does not by itself
mean the path is broken: Hop 12 still answers.
```

---

## 10. Limitations

* **No raw sockets / no WinPcap.** A pure-standard-library program cannot craft
  its own ICMP packet with a custom TTL, so route discovery wraps the Windows
  system `tracert` (isolated inside `traceroute.py`) and measures RTT with
  ordinary ICMP echo requests via `subprocess`. This is why the project runs
  without administrator rights; a raw-socket version would need them.
* **Hop-to-IP mapping comes from `tracert`.** `tracert` returns one sample per
  TTL, so a hop that suppressed ICMP for `tracert` may still answer our
  repeated probes, or vice versa. This is inherent to traceroute.
* **Geolocation is not attempted.** HopCheck reports IPs and latency, never
  city/ISP names.
* **IPv6 is supported for tracing, not for split-horizon comparison.** A trace
  starts as IPv4 and is retried over the default (IPv6-capable) family whenever
  the destination is *not reached*, because an IPv6-native network often answers
  only for IPv6. Whichever attempt got further is kept and the run states which
  family was used. Latency is still compared hop-to-hop within a single trace, so
  a route that mixes both families is reported as the untraceable case rather than
  as a jump.
* **`tracert` output is locale-dependent.** Parsing covers the English Windows
  format; a different system language may need the parser adjusted.
* **Asymmetric routing.** The forward path and return path may differ, so a
  single RTT is an approximation of round-trip cost, not one-way delay.
* **One run is a snapshot.** Interference and load balancing change results
  between runs; conclusions are indicative, not proof.
* **No IPv6 support** — the analysis works on IPv4 only.

---

## 11. Future Improvements

* Raw-socket / Scapy-based probing to set the TTL ourselves and drop the
  `tracert` dependency (requires administrator rights or Npcap).
* IPv6 support alongside IPv4.
* Repeated runs over time to plot a latency graph and detect when a hop
  *becomes* slow rather than merely being slow.
* Asymmetric-path detection by probing the reverse direction.
* Export of results to CSV for offline comparison.
* Optional reverse-DNS lookup for friendlier hop labels.

---

## Project Structure

```
hopcheck/
│
├── hopcheck.py          # main entry point: UI, flow, reporting
├── traceroute.py        # Windows TTL route discovery + RTT probing
├── analyzer.py          # statistics, persistence logic, diagnosis text
├── utils.py             # input validation + formatting helpers
├── requirements.txt     # empty by design (standard library only)
├── README.md            # this file
└── tests/
    ├── test_analyzer.py    # unit tests for the analysis logic (the 5 key cases)
    ├── test_utils.py       # unit tests for validation / formatting
    ├── test_traceroute.py  # unit tests for the tracert / ping output parsers
    └── test_hopcheck.py    # unit tests for the CLI layer and diagnosis text
```

Run the tests (no internet connection required):

```powershell
python -m unittest discover -s tests -v
```

The suite has 128 tests covering the analysis rules, the Windows command-line
output parsers, name resolution and IPv6 fallback, the input validation, the
terminal formatting and the diagnosis text.

---

