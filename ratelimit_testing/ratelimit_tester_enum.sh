#!/bin/bash

# Advanced Rate Limit Tester with Wordlist and Proper Concurrent Rotation
# Usage: ./rate_limit_tester_wordlist_fixed.sh [OPTIONS]

URL=""
WORDLIST=""
REQUESTS_PER_BURST=180
WAIT_TIME=15
TOTAL_BURSTS=3
REQUEST_DELAY=0
SHOW_RESPONSES=false
METHOD="GET"
HEADERS=""
PLACEHOLDER="{FUZZ}"
CYCLE_MODE="sequential"
MAX_WORDLIST_ITEMS=0
RATE_LIMIT_SCOPE="test"
DATA=""
VERBOSE=false
SUCCESS_CODES="200,201,202,204"
CONCURRENCY=1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $0 -u URL [OPTIONS]

Required:
    -u URL              Target URL with placeholder (e.g., https://api.example.com/user/{FUZZ})

Wordlist Options:
    -w FILE             Wordlist file
    -p PLACEHOLDER      Placeholder (default: {FUZZ})
    -c MODE             Cycle mode: sequential, random, rotate (default: sequential)
    -L NUM              Limit wordlist items (0 = all)

Rate Limiting:
    -r NUM              Requests per burst (default: 180)
    -t SECONDS          Wait between bursts (default: 15)
    -b NUM              Total bursts (default: 3)
    -d SECONDS          Delay between requests (default: 0)
    -j NUM              Concurrent requests (default: 1)
    -S CODES            Success codes (default: 200,201,202,204)

Request:
    -m METHOD           HTTP method (default: GET)
    -H HEADER           Custom header
    -D DATA             POST/PUT data
    -s                  Show each response
    -v                  Verbose progress
    -h                  Help

Examples:
    # 10 concurrent with proper rotation
    $0 -u "https://api.example.com/users/{FUZZ}" -w users.txt -j 10 -v

    # Max speed
    $0 -u "https://api.example.com/users/{FUZZ}" -w users.txt -j 50 -r 500 -v

EOF
    exit 1
}

while getopts "u:w:p:c:L:r:t:b:d:j:S:m:H:D:svh" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        p) PLACEHOLDER="$OPTARG" ;;
        c) CYCLE_MODE="$OPTARG" ;;
        L) MAX_WORDLIST_ITEMS="$OPTARG" ;;
        r) REQUESTS_PER_BURST="$OPTARG" ;;
        t) WAIT_TIME="$OPTARG" ;;
        b) TOTAL_BURSTS="$OPTARG" ;;
        d) REQUEST_DELAY="$OPTARG" ;;
        j) CONCURRENCY="$OPTARG" ;;
        S) SUCCESS_CODES="$OPTARG" ;;
        m) METHOD="$OPTARG" ;;
        H) HEADERS="${HEADERS} -H \"$OPTARG\"" ;;
        D) DATA="$OPTARG" ;;
        s) SHOW_RESPONSES=true ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$URL" ]; then
    echo -e "${RED}Error: URL required${NC}"
    usage
fi

# Parse success codes
IFS=',' read -ra SUCCESS_CODE_ARRAY <<< "$SUCCESS_CODES"

# Load wordlist
declare -a WORDLIST_ITEMS
if [ -n "$WORDLIST" ]; then
    if [ ! -f "$WORDLIST" ]; then
        echo -e "${RED}Error: Wordlist not found: $WORDLIST${NC}"
        exit 1
    fi
    
    mapfile -t WORDLIST_ITEMS < "$WORDLIST"
    temp_array=()
    for item in "${WORDLIST_ITEMS[@]}"; do
        trimmed=$(echo "$item" | tr -d '[:space:]')
        if [ -n "$trimmed" ]; then
            temp_array+=("$trimmed")
        fi
    done
    WORDLIST_ITEMS=("${temp_array[@]}")
    
    if [ "$MAX_WORDLIST_ITEMS" -gt 0 ] && [ "${#WORDLIST_ITEMS[@]}" -gt "$MAX_WORDLIST_ITEMS" ]; then
        WORDLIST_ITEMS=("${WORDLIST_ITEMS[@]:0:$MAX_WORDLIST_ITEMS}")
    fi
    
    if [ "${#WORDLIST_ITEMS[@]}" -eq 0 ]; then
        echo -e "${RED}Error: Wordlist is empty${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Loaded ${#WORDLIST_ITEMS[@]} items from wordlist${NC}"
    
    if [ "${#WORDLIST_ITEMS[@]}" -lt "$((REQUESTS_PER_BURST * TOTAL_BURSTS))" ]; then
        echo -e "${YELLOW}Note: Will rotate through wordlist to complete all requests${NC}"
    fi
fi

echo -e "${BLUE}=== Advanced Rate Limit Tester ===${NC}"
echo -e "${BLUE}URL:${NC} $URL"
if [ -n "$WORDLIST" ]; then
    echo -e "${BLUE}Wordlist:${NC} ${#WORDLIST_ITEMS[@]} items"
fi
echo -e "${BLUE}Requests per burst:${NC} $REQUESTS_PER_BURST"
echo -e "${BLUE}Concurrency:${NC} $CONCURRENCY"
echo -e "${BLUE}Success codes:${NC} $SUCCESS_CODES"
echo ""

TEMP_DIR=$(mktemp -d)
STATS_FILE="$TEMP_DIR/stats"
touch "$STATS_FILE"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# PRE-GENERATE all values
declare -a REQUEST_VALUES
if [ "${#WORDLIST_ITEMS[@]}" -gt 0 ]; then
    current_index=0
    for ((i=0; i<REQUESTS_PER_BURST*TOTAL_BURSTS; i++)); do
        case "$CYCLE_MODE" in
            sequential|rotate)
                REQUEST_VALUES[$i]="${WORDLIST_ITEMS[$current_index]}"
                current_index=$((current_index + 1))
                if [ $current_index -ge "${#WORDLIST_ITEMS[@]}" ]; then
                    current_index=0
                fi
                ;;
            random)
                local idx=$((RANDOM % ${#WORDLIST_ITEMS[@]}))
                REQUEST_VALUES[$i]="${WORDLIST_ITEMS[$idx]}"
                ;;
        esac
    done
fi

is_success_code() {
    local code="$1"
    for success_code in "${SUCCESS_CODE_ARRAY[@]}"; do
        if [ "$code" = "$success_code" ]; then
            return 0
        fi
    done
    return 1
}

make_request() {
    local request_num=$1
    local burst_num=$2
    local wordlist_value="$3"
    
    # Substitute placeholder
    final_url="$URL"
    final_headers="$HEADERS"
    final_data="$DATA"
    
    if [ -n "$wordlist_value" ]; then
        final_url="${URL//$PLACEHOLDER/$wordlist_value}"
        final_headers="${HEADERS//$PLACEHOLDER/$wordlist_value}"
        final_data="${DATA//$PLACEHOLDER/$wordlist_value}"
    fi
    
    # Make request
    local status_code
    local curl_base="curl -X '$METHOD' --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}'"
    
    if [ -n "$final_data" ]; then
        curl_base="$curl_base -d '$final_data'"
    fi
    
    if [ -n "$final_headers" ]; then
        status_code=$(eval "$curl_base $final_headers '$final_url'" 2>/dev/null || echo "000")
    else
        status_code=$(curl -X "$METHOD" --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}' "$final_url" 2>/dev/null || echo "000")
    fi
    
    # Write to stats file
    echo "$status_code:$wordlist_value" >> "$STATS_FILE"
    
    # Show responses
    if [ "$SHOW_RESPONSES" = true ]; then
        local display_value=""
        if [ -n "$wordlist_value" ]; then
            display_value=" [${CYAN}$wordlist_value${NC}]"
        fi
        
        if is_success_code "$status_code"; then
            echo -e "Burst $burst_num, Request $request_num$display_value: ${GREEN}$status_code${NC}"
        elif [[ "$status_code" == "429" ]]; then
            echo -e "Burst $burst_num, Request $request_num$display_value: ${YELLOW}$status_code (Rate Limited)${NC}"
        else
            echo -e "Burst $burst_num, Request $request_num$display_value: ${RED}$status_code${NC}"
        fi
    fi
}

# Main loop
request_index=0

for ((burst=1; burst<=TOTAL_BURSTS; burst++)); do
    echo -e "${YELLOW}--- Burst $burst/$TOTAL_BURSTS ---${NC}"
    
    for ((i=1; i<=REQUESTS_PER_BURST; i++)); do
        # Get pre-generated value
        value="${REQUEST_VALUES[$request_index]}"
        request_index=$((request_index + 1))
        
        # Launch in background
        make_request "$i" "$burst" "$value" &
        
        if [ "$VERBOSE" = true ]; then
            if [ -n "$value" ]; then
                echo -ne "\rBurst $burst: $i/$REQUESTS_PER_BURST [${value:0:20}]...      "
            else
                echo -ne "\rBurst $burst: $i/$REQUESTS_PER_BURST...      "
            fi
        fi
        
        # Wait if concurrency limit reached
        if [ $((i % CONCURRENCY)) -eq 0 ]; then
            wait
            if (( $(echo "$REQUEST_DELAY > 0" | bc -l) )); then
                sleep "$REQUEST_DELAY"
            fi
        fi
    done
    
    wait
    
    if [ "$VERBOSE" = true ]; then
        echo ""
    fi
    
    echo -e "${GREEN}Completed burst $burst${NC}"
    
    if [ "$SHOW_RESPONSES" = false ]; then
        echo "Status codes:"
        cut -d: -f1 "$STATS_FILE" | sort | uniq -c | while read count code; do
            if is_success_code "$code"; then
                echo -e "  ${GREEN}$code${NC}: $count"
            elif [[ "$code" == "429" ]]; then
                echo -e "  ${YELLOW}$code (Rate Limited)${NC}: $count"
            else
                echo -e "  ${RED}$code${NC}: $count"
            fi
        done
    fi
    
    if [ "$burst" -lt "$TOTAL_BURSTS" ]; then
        echo -e "${BLUE}Waiting $WAIT_TIME seconds...${NC}"
        sleep "$WAIT_TIME"
        echo ""
    fi
done

# Final summary
echo ""
echo -e "${BLUE}=== Test Complete ===${NC}"

total_requests=$(wc -l < "$STATS_FILE")
echo -e "${BLUE}Total requests:${NC} $total_requests"

total_success=0
total_errors=0

while IFS=: read code value; do
    if is_success_code "$code"; then
        ((total_success++))
    else
        ((total_errors++))
    fi
done < "$STATS_FILE"

echo -e "${GREEN}Successful ($SUCCESS_CODES):${NC} $total_success"
echo -e "${RED}Errors/Other:${NC} $total_errors"
echo ""

cut -d: -f1 "$STATS_FILE" | sort | uniq -c | sort -rn | while read count code; do
    pct=$(awk "BEGIN {printf \"%.1f\", ($count/$total_requests)*100}")
    
    if is_success_code "$code"; then
        echo -e "  ${GREEN}$code${NC}: $count ($pct%)"
    elif [[ "$code" == "429" ]]; then
        echo -e "  ${YELLOW}$code (Rate Limited)${NC}: $count ($pct%)"
    elif [[ "$code" == "000" ]]; then
        echo -e "  ${RED}$code (Connection Failed)${NC}: $count ($pct%)"
    else
        echo -e "  ${RED}$code${NC}: $count ($pct%)"
    fi
done

echo ""
if grep -q "^429:" "$STATS_FILE"; then
    echo -e "${GREEN}✓ Rate limiting detected${NC}"
else
    echo -e "${YELLOW}✗ No rate limiting detected${NC}"
    if [ "${#WORDLIST_ITEMS[@]}" -gt 0 ]; then
        echo -e "${CYAN}→ Possible bypass via parameter variation${NC}"
    fi
fi
