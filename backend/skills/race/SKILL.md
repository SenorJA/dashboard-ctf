---
name: race
description: "Race conditions and TOCTOU — limit bypasses, double-spend, coupon reuse, race-based business logic flaws."
category: race
allowed_tools:
  - curl
  - ffuf
  - python
version: "1.0.0"
author: "MIRV"
---

# Race Condition Methodology

## 1. Identify candidates
Operations with side-effects and a one-time / limited token:
- ` redeem` / `applyCoupon` / `useVoucher`
- ` transfer` / ` withdraw` / `deposit`
- ` vote` / ` submitForm` / ` claimReward`
- ` changeEmail` with single-use confirmation token
- ` resetPassword` with reused single-use token
- Balance/credit decrement flows: query → check → deduct (classic TOCTOU)

## 2. Send N concurrent identical requests
### ffuf single-burst (cluster-bomb 100 tokens)
```bash
seq 100 | ffuf -u {url} -X POST -d '{"code":"VIP"}' -mc all -t 100 -mode cluster-bomb
```
(legacy `-mode cluster-bomb` deprecated; use `-t 100` with single wordlist via stdin)
### Python asyncio parallel POSTs
```python
import asyncio, httpx, sys
URL = sys.argv[1]
BODY = {"code": "VIP", "user": "u1"}
async def fire(cl):
    r = await cl.post(URL, json=BODY)
    return r.status_code, r.text[:120]
async def main():
    async with httpx.AsyncClient(http2=False) as cl:
        async with asyncio.TaskGroup() as g:
            for _ in range(50):
                g.create_task(fire(cl))
if __name__ == "__main__":
    asyncio.run(main())
```

## 3. Compare pre/post state
- Snapshot before: `SELECT uses FROM coupons WHERE code='VIP'` / balance
- After burst: count accepted (`status==200` + body `"applied"`) vs DB increment
- If accepted N > 1 for a single-use coupon → race confirmed
- Verify with a clean token each run to rule out false positives

## 4. Common patterns
- Single-use validation TOCTOU: `if (used) return 400; used=true;` across threads
  both pass the check before either sets the flag
- Balance query before deduction (read-check-write race)
- File lock / `O_CREAT` exclusive flagging races
- DB foreign-key cascade race (insert child then delete parent)
- Coupon/voucher re-use: only one redemption per user → fire from same session

## 5. Reliable reproduction
- Use Turbo Intruder `@myengine` with single-packet `engine = RequestEngine(
  endpoint, engine=Engine.BURP2)` to land on same TCP packet (final-byte sync)
- Run burst from a host with low RTT (same VPC) to remove jitter
- Disable HTTP/2 multiplex interference by using HTTP/1.1
- Iteratively increase `-t` until the exploit stabilizes (50, 100, 200)
- Some apps need a warm-up request to prime session caches

## IMPORTANT
- Always restore state after testing (delete extra credits, refunds)
- Single packet burst is the gold standard — older threadpools miss the race
- Document: pre-state, post-state, count of overlap-success responses
- If exploit is flaky, late-stage 5σ confirmation requires ≥10 successful duplicates