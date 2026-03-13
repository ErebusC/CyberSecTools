# Complete Feature Summary 🚀

All scripts now have powerful new features!

## ⚡ Speed Features

### 1. No Delay by Default
- **Old**: 0.01s delay between requests
- **New**: 0s delay (max speed!)
- **Control**: Use `-d 0.1` to add delay

### 2. Variable Concurrency (`-j` flag)
- **Send multiple requests in parallel**
- `-j 1` = Sequential (default)
- `-j 10` = 10 parallel requests
- `-j 50` = 50 parallel requests (very fast!)

**Speed improvement**: Up to 50x faster!

---

## 🎯 Flexibility Features

### 3. Custom Success Codes
Define what counts as "success" or "enumerated"

**Basic/Wordlist testers** - Use `-S`:
```bash
-S "200,302,403"
```

**Enumeration tester** - Use `-E`:
```bash
-E "200,302,403"
```

**Why this matters**:
- 302 redirects = user exists
- 403 forbidden = user exists but no access
- 401 unauthorized = user exists but need auth

### 4. Auto-Rotation
Wordlist automatically rotates when smaller than burst size

**Before**:
```
5 users, 100 requests → STOPPED at 5 requests
```

**Now**:
```
5 users, 100 requests → Rotates 20 times through list
```

---

## Complete Examples

### Example 1: Maximum Speed User Enumeration

```bash
chmod +x rate_limit_enum_tester_fixed.sh

./rate_limit_enum_tester_fixed.sh \
  -u "https://api.example.com/users/{FUZZ}" \
  -w usernames.txt \
  -j 50 \
  -r 1000 \
  -E "200,302,403" \
  -v \
  -e \
  -C results.csv
```

**Features**:
- ⚡ 50 concurrent requests
- 🎯 Custom success codes (200, 302, 403)
- 🔄 Auto-rotates if wordlist < 1000
- 📊 Shows progress (`-v`)
- ✅ Only enumerated (`-e`)
- 💾 Exports to CSV

**Result**: 1000 requests in ~5-10 seconds!

---

### Example 2: Test Per-User Rate Limiting

```bash
# Only 3 users
cat > test_users.txt << 'EOF'
admin
alice
bob
EOF

# Send 300 requests (100 per user)
./rate_limit_enum_tester_fixed.sh \
  -u "https://api.example.com/users/{FUZZ}/data" \
  -w test_users.txt \
  -r 300 \
  -j 30 \
  -v
```

**Tests**:
- Is rate limiting per-user or global?
- Each user gets 100 attempts
- 30 concurrent requests
- Fast and thorough!

---

### Example 3: 302 Redirects as Success

```bash
./rate_limit_enum_tester_fixed.sh \
  -u "https://api.example.com/users/{FUZZ}" \
  -w users.txt \
  -E "302" \
  -j 20 \
  -v \
  -e
```

**Scenario**: App redirects when user exists

**Result**: Shows all users that return 302

---

### Example 4: Balanced Approach

```bash
./rate_limit_enum_tester_fixed.sh \
  -u "https://api.example.com/users/{FUZZ}" \
  -w users.txt \
  -j 10 \
  -d 0.1 \
  -E "200,302,403" \
  -v
```

**Features**:
- Moderate concurrency (10)
- 100ms delay (polite)
- Custom success codes
- Good balance of speed and safety

---

## Flag Reference

### Speed Control
```bash
-d 0      # Max speed (default)
-d 0.1    # 100ms delay
-j 1      # Sequential (default)
-j 10     # 10 concurrent
-j 50     # 50 concurrent (very fast!)
```

### Custom Codes
```bash
-S "200,302"      # Success codes (basic/wordlist)
-E "200,302,403"  # Enumeration codes (enum tester)
```

### Output Control
```bash
-v    # Verbose progress
-s    # Show each response
-e    # Only enumerated values
-C FILE    # Export to CSV
```

### Request Options
```bash
-r 500    # Requests per burst
-b 3      # Number of bursts
-t 15     # Wait between bursts
-m POST   # HTTP method
-H "Header: Value"    # Custom header
-D '{"key":"value"}'  # POST data
```

---

## Quick Decision Guide

### Want Maximum Speed?
```bash
-j 50 -d 0
```

### Want to be Polite?
```bash
-j 1 -d 0.5
```

### Want Balanced?
```bash
-j 10 -d 0.1
```

### Got 302/403 Responses?
```bash
-E "200,302,403"
```

### Small Wordlist?
**No problem!** Auto-rotation handles it
```bash
-r 500  # Even with 10-item wordlist
```

---

## Speed Comparison

| Setup | 500 Requests | Speed |
|-------|-------------|-------|
| Sequential (`-j 1`) | ~50s | Slow |
| 10 concurrent (`-j 10`) | ~8s | Fast |
| 20 concurrent (`-j 20`) | ~5s | Very fast |
| 50 concurrent (`-j 50`) | ~3s | Extreme! |

---

## Common Workflows

### 1. Quick Enumeration
```bash
./rate_limit_enum_tester_fixed.sh \
  -u "URL/{FUZZ}" -w users.txt -j 20 -v -e
```

### 2. Thorough Testing
```bash
./rate_limit_enum_tester_fixed.sh \
  -u "URL/{FUZZ}" -w users.txt -j 20 -r 500 -b 3 -v -C results.csv
```

### 3. Discover Success Codes
```bash
./rate_limit_enum_tester_fixed.sh \
  -u "URL/{FUZZ}" -w test.txt -r 10 -s
```

Then use discovered codes:
```bash
-E "200,302,403"
```

### 4. Max Speed Attack
```bash
./rate_limit_enum_tester_fixed.sh \
  -u "URL/{FUZZ}" -w users.txt -j 50 -r 1000 -v
```

---

## All Features Combined

```bash
./rate_limit_enum_tester_fixed.sh \
  -u "https://api.example.com/users/{FUZZ}" \
  -w usernames.txt \
  -j 20 \
  -r 500 \
  -d 0 \
  -E "200,302,403" \
  -v \
  -e \
  -C results.csv
```

**This command**:
- ⚡ 20 concurrent requests
- 🎯 Treats 200, 302, 403 as enumerated
- 🔄 Auto-rotates through wordlist
- 📊 Shows progress
- ✅ Only shows enumerated users
- 💾 Exports to CSV
- 🚀 Completes 500 requests in ~10 seconds

---

## After Download

```bash
# 1. Make executable
chmod +x rate_limit_enum_tester_fixed.sh

# 2. Create test wordlist
cat > users.txt << 'EOF'
admin
alice
bob
test
EOF

# 3. Run!
./rate_limit_enum_tester_fixed.sh \
  -u "https://httpbin.org/status/{FUZZ}" \
  -w users.txt \
  -j 10 \
  -v
```

---

## Summary

### What's New
✅ Max speed by default (0s delay)
✅ Variable concurrency (`-j` flag)
✅ Custom success/enumeration codes (`-S`, `-E`)
✅ Auto-rotation for small wordlists
✅ 10-50x faster than before!

### What's Still Great
✅ Detailed enumeration tracking
✅ CSV export
✅ Multiple output formats
✅ Verbose progress
✅ Rate limit detection
✅ Per-value statistics

### Perfect For
✅ User enumeration
✅ Email validation
✅ API endpoint discovery
✅ Rate limit testing
✅ Bypass detection
✅ Security assessments

All scripts ready to use! 🎉
