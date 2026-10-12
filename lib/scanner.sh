#!/usr/bin/env bash

get_random_value() {
    local -n arr="$1"
    echo "${arr[$(( RANDOM % ${#arr[@]} ))]}"
}

get_unique_combination_legacy() {
    local packets=""
    local length=""
    local interval=""
    local combination=""

    while true; do
        packets="$(get_random_value packetsOptions)"
        length="$(get_random_value lengthOptions)"
        interval="$(get_random_value legacyIntervalOptions)"

        combination="${packets},${length},${interval}"

        if [[ -z "${USED_COMBINATIONS[$combination]+x}" ]]; then
            USED_COMBINATIONS["$combination"]=1
            SCAN_COMBINATION="$packets|$length|$interval"
            return
        fi
    done
}

get_unique_combination_finalmask() {
    local packets=""
    local length=""
    local delay=""
    local max_split=""
    local combination=""

    while true; do
        packets="$(get_random_value packetsOptions)"
        length="$(get_random_value lengthOptions)"
        delay="$(get_random_value finalmaskDelayOptions)"
        max_split="$(get_random_value maxSplitOptions)"

        combination="${packets},${length},${delay},${max_split}"

        if [[ -z "${USED_COMBINATIONS[$combination]+x}" ]]; then
            USED_COMBINATIONS["$combination"]=1
            SCAN_COMBINATION="$packets|$length|$delay|$max_split"
            return
        fi
    done
}

send_http_request() {
    local request_count="$1"
    local timeout_sec="$2"
    local timeout_ms=$(( timeout_sec * 1000 ))
    local url="http://cp.cloudflare.com"
    local times=()
    local elapsed=""
    local rc=0
    local ms=""
    local total="0"
    local valid=0
    local failed=0
    local avg="0"

    for ((i = 1; i <= request_count; i++)); do
        elapsed="$(
            curl \
                --silent \
                --output /dev/null \
                --write-out "%{time_total}" \
                --max-time "$timeout_sec" \
                --proxy "http://${HTTP_PROXY_SERVER}:${HTTP_PROXY_PORT}" \
                "$url" 2>/dev/null
        )"

        rc=$?

        if [[ $rc -eq 0 && "$elapsed" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            ms="$(awk -v t="$elapsed" 'BEGIN { printf "%.2f", t * 1000 }')"
            times+=("$ms")
        else
            times+=("-1")
        fi

        sleep 1
    done

    # Drop first request because it is often warmer/noisier.
    times=("${times[@]:1}")

    echo "Individual Request Times:" >> "$LOG_FILE"
    IFS=','; echo "${times[*]}" >> "$LOG_FILE"; unset IFS

    for t in "${times[@]}"; do
        if [[ "$t" == "-1" ]]; then
            ((failed++))
        else
            total="$(awk -v a="$total" -v b="$t" 'BEGIN { print a + b }')"
            ((valid++))
        fi
    done

    if (( valid > 0 )); then
        avg="$(awk -v total="$total" -v failed="$failed" -v timeout="$timeout_ms" -v n="${#times[@]}" \
            'BEGIN { printf "%.2f", (total + failed * timeout) / n }')"
    else
        avg="0"
    fi

    echo "$avg"
}

validate_instance_count() {
    local maxPossibleInstances=0

    if is_finalmask_mode; then
        maxPossibleInstances=$(( ${#packetsOptions[@]} * ${#lengthOptions[@]} * ${#finalmaskDelayOptions[@]} * ${#maxSplitOptions[@]} ))
    else
        maxPossibleInstances=$(( ${#packetsOptions[@]} * ${#lengthOptions[@]} * ${#legacyIntervalOptions[@]} ))
    fi

    while (( Instances > maxPossibleInstances )); do
        echo "Error: Number of instances cannot be greater than $maxPossibleInstances"
        read -r -p "Enter the number of instances default 10: " InstancesInput
        Instances="${InstancesInput:-10}"
    done
}

print_table_header() {
    if is_finalmask_mode; then
        printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
        printf '|   Instance   |     Packets     |    Length     |      Delay      |   Max Split   | Average Ping  |\n'
        printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
    else
        printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
        printf '|   Instance   |     Packets     |    Length     |    Interval     | Average Ping  |\n'
        printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
    fi
}

print_table_footer() {
    if is_finalmask_mode; then
        printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
    else
        printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
    fi
}

run_scan() {
    local combination=""
    local packets=""
    local length=""
    local delay=""
    local max_split=""
    local averagePing=""
    local displayPing=""

    declare -gA USED_COMBINATIONS
    declare -ga RESULTS
    USED_COMBINATIONS=()
    RESULTS=()

    print_table_header

    for ((i = 0; i < Instances; i++)); do
        if is_finalmask_mode; then
            get_unique_combination_finalmask
            combination="$SCAN_COMBINATION"

            packets="$(echo "$combination" | cut -d'|' -f1)"
            length="$(echo "$combination" | cut -d'|' -f2)"
            delay="$(echo "$combination" | cut -d'|' -f3)"
            max_split="$(echo "$combination" | cut -d'|' -f4)"

            modify_config_finalmask "$packets" "$length" "$delay" "$max_split"
        else
            get_unique_combination_legacy
            combination="$SCAN_COMBINATION"

            packets="$(echo "$combination" | cut -d'|' -f1)"
            length="$(echo "$combination" | cut -d'|' -f2)"
            delay="$(echo "$combination" | cut -d'|' -f3)"
            max_split="-"

            modify_config_legacy "$packets" "$length" "$delay"
        fi

        start_xray_for_test

        if is_finalmask_mode; then
            echo "Testing packets=$packets, length=$length, delay=$delay, maxSplit=$max_split..." >> "$LOG_FILE"
        else
            echo "Testing packets=$packets, length=$length, interval=$delay..." >> "$LOG_FILE"
        fi

        averagePing="$(send_http_request "$RequestCount" "$TimeoutSec")"

        echo "Average Response Time: $averagePing ms" >> "$LOG_FILE"
        echo >> "$LOG_FILE"

        RESULTS+=("${averagePing}|$((i + 1))|${packets}|${length}|${delay}|${max_split}")

        if [[ "$averagePing" == "0" ]]; then
            displayPing="FAILED"
        else
            displayPing="$averagePing"
        fi

        if is_finalmask_mode; then
            printf '|    %-9s | %-15s | %-13s | %-15s | %-13s | %-13s |\n' \
                "$((i + 1))" "$packets" "$length" "$delay" "$max_split" "$displayPing"
        else
            printf '|    %-9s | %-15s | %-13s | %-15s | %-13s |\n' \
                "$((i + 1))" "$packets" "$length" "$delay" "$displayPing"
        fi

        sleep 1
    done

    print_table_footer
}

print_top_results() {
    echo
    echo "Top three lowest average response times:"
    echo

    if is_finalmask_mode; then
        printf '%-10s %-12s %-12s %-12s %-12s %-24s\n' \
            "Instance" "Packets" "Length" "Delay" "MaxSplit" "AverageResponseTime(ms)"
    else
        printf '%-10s %-12s %-12s %-12s %-24s\n' \
            "Instance" "Packets" "Length" "Interval" "AverageResponseTime(ms)"
    fi

    printf '%s\n' "${RESULTS[@]}" \
        | awk -F'|' '$1 > 0 { print }' \
        | sort -t'|' -k1,1n \
        | head -n 3 \
        | while IFS='|' read -r avg instance packets length delay max_split; do
            if is_finalmask_mode; then
                printf '%-10s %-12s %-12s %-12s %-12s %-24s\n' \
                    "$instance" "$packets" "$length" "$delay" "$max_split" "$avg"
            else
                printf '%-10s %-12s %-12s %-12s %-24s\n' \
                    "$instance" "$packets" "$length" "$delay" "$avg"
            fi
          done
}

print_output_files() {
    echo
    echo "Files:"
    echo "Config:        $CONFIG_PATH"
    echo "Config backup: $CONFIG_BACKUP"
    echo "Ping log:      $LOG_FILE"
    echo "Xray log:      $XRAY_LOG_FILE"
    echo "Xray errors:   $XRAY_ERROR_LOG_FILE"
}
