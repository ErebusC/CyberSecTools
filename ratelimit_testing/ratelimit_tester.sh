#!/bin/bash

# Rate Limit Tester with Concurrency
# Tests application rate limiting with parallel requests
# Usage: ./rate_limit_tester_fixed.sh [OPTIONS]

URL=""
REQUESTS_PER_BURST=180
WAIT_TIME=15
TOTAL_BURSTS=3
REQUEST_DELAY=0
SHOW_RESPONSES=false
METHOD="GET"
HEADERS=""
VERBOSE=false
SUCCESS_CODES="200,201,202,204"
CONCURRENCY=1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $0 -u URL [OPTIONS]

Required:
    -u URL              Target URL to test

Options:
    -r NUM              Requests per burst (default: 180)
    -w SECONDS          Wait time between bursts (default: 15)
    -b NUM              Total number of bursts (default: 3)
    -d SECONDS          Delay between requests (default: 0)
    -j NUM              Concurrent requests (default: 1)
    -S CODES            Success status codes (default: 200,201,202,204)
    -m METHOD           HTTP method (default: GET)
    -H HEADER           Add custom header
    -s                  Show response codes for each request
    -v                  Verbose (show progress counter)
    -h                  Show help

Examples:
    $0 -u https://api.example.com/endpoint -r 100
    $0 -u https://api.example.com/endpoint -r 100 -j 10 -v
    $0 -u https://api.example.com/endpoint -r 500 -j 50 -v

EOF
    exit 1
}

while getopts "u:r:w:b:d:j:S:m:H:svh" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        r) REQUESTS_PER_BURST="$OPTARG" ;;
        w) WAIT_TIME="$OPTARG" ;;
        b) TOTAL_BURSTS="$OPTARG" ;;
        d) REQUEST_DELAY="$OPTARG" ;;
        j) CONCURRENCY="$OPTARG" ;;
        S) SUCCESS_CODES="$OPTARG" ;;
        m) METHOD="$OPTARG" ;;
        H) HEADERS="${HEADERS} -H \"$OPTARG\"" ;;
        s) SHOW_RESPONSES=true ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$URL" ]; then
    echo -e "${RED}Error: URL is required${NC}"
    usage
fi

IFS=',' read -ra SUCCESS_CODE_ARRAY <<< "$SUCCESS_CODES"

echo -e "${BLUE}=== Rate Limit Tester ===${NC}"
echo -e "${BLUE}URL:${NC} $URL"
echo -e "${BLUE}Method:${NC} $METHOD"
echo -e "${BLUE}Requests per burst:${NC} $REQUESTS_PER_BURST"
echo -e "${BLUE}Concurrency:${NC} $CONCURRENCY"
echo -e "${BLUE}Wait time:${NC} $WAIT_TIME seconds"
echo -e "${BLUE}Total bursts:${NC} $TOTAL_BURSTS"
echo -e "${BLUE}Success codes:${NC} $SUCCESS_CODES"
echo ""

TEMP_DIR=$(mktemp -d)
STATS_FILE="$TEMP_DIR/stats"
touch "$STATS_FILE"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

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
    
    # Make curl request with timeouts
    local status_code
    if [ -n "$HEADERS" ]; then
        status_code=$(eval "curl -X '$METHOD' --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}' $HEADERS '$URL'" 2>/dev/null || echo "000")
    else
        status_code=$(curl -X "$METHOD" --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || echo "000")
    fi
    
    # Write result to stats file
    echo "$status_code" >> "$STATS_FILE"
    
    # Show individual responses if requested
    if [ "$SHOW_RESPONSES" = true ]; then
        if is_success_code "$status_code"; then
            echo -e "Burst $burst_num, Request $request_num: ${GREEN}$status_code${NC}"
        elif [[ "$status_code" == "429" ]]; then
            echo -e "Burst $burst_num, Request $request_num: ${YELLOW}$status_code (Rate Limited)${NC}"
        elif [[ "$status_code" == "000" ]]; then
            echo -e "Burst $burst_num, Request $request_num: ${RED}$status_code (Connection Failed)${NC}"
        else
            echo -e "Burst $burst_num, Request $request_num: ${RED}$status_code${NC}"
        fi
    fi
}

# Main loop
for ((burst=1; burst<=TOTAL_BURSTS; burst++)); do
    echo -e "${YELLOW}--- Burst $burst/$TOTAL_BURSTS ---${NC}"
    
    for ((i=1; i<=REQUESTS_PER_BURST; i++)); do
        # Launch request in background
        make_request "$i" "$burst" &
        
        # Show progress
        if [ "$VERBOSE" = true ]; then
            echo -ne "\rBurst $burst: $i/$REQUESTS_PER_BURST requests launched..."
        fi
        
        # Wait if we've reached concurrency limit
        if [ $((i % CONCURRENCY)) -eq 0 ]; then
            wait
            
            # Only sleep if delay is set
            if (( $(echo "$REQUEST_DELAY > 0" | bc -l) )); then
                sleep "$REQUEST_DELAY"
            fi
        fi
    done
    
    # Wait for remaining requests
    wait
    
    if [ "$VERBOSE" = true ]; then
        echo ""
    fi
    
    echo -e "${GREEN}Completed $REQUESTS_PER_BURST requests${NC}"
    
    # Count responses from stats file
    if [ "$SHOW_RESPONSES" = false ]; then
        echo "Status codes:"
        sort "$STATS_FILE" | uniq -c | while read count code; do
            if is_success_code "$code"; then
                echo -e "  ${GREEN}$code${NC}: $count"
            elif [[ "$code" == "429" ]]; then
                echo -e "  ${YELLOW}$code (Rate Limited)${NC}: $count"
            else
                echo -e "  ${RED}$code${NC}: $count"
            fi
        done
    fi
    
    # Wait between bursts
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

# Count success and errors
total_success=0
total_errors=0

while read code; do
    if is_success_code "$code"; then
        ((total_success++))
    else
        ((total_errors++))
    fi
done < "$STATS_FILE"

echo -e "${GREEN}Successful ($SUCCESS_CODES):${NC} $total_success"
echo -e "${RED}Errors/Other:${NC} $total_errors"
echo ""
echo -e "${BLUE}Final Status Code Summary:${NC}"

sort "$STATS_FILE" | uniq -c | sort -rn | while read count code; do
    percentage=$(awk "BEGIN {printf \"%.1f\", ($count/$total_requests)*100}")
    
    if is_success_code "$code"; then
        echo -e "  ${GREEN}$code${NC}: $count ($percentage%)"
    elif [[ "$code" == "429" ]]; then
        echo -e "  ${YELLOW}$code (Rate Limited)${NC}: $count ($percentage%)"
    elif [[ "$code" == "000" ]]; then
        echo -e "  ${RED}$code (Connection Failed)${NC}: $count ($percentage%)"
    else
        echo -e "  ${RED}$code${NC}: $count ($percentage%)"
    fi
done

# Check for rate limiting
echo ""
if grep -q "^429$" "$STATS_FILE"; then
    echo -e "${GREEN}✓ Rate limiting WORKING${NC} - Received 429 responses"
else
    echo -e "${YELLOW}✗ No rate limiting detected${NC}"
fi
