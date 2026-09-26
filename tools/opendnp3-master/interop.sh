#!/usr/bin/env bash
# Runs the simulator headless and drives it with the opendnp3 masters. Run build.sh first.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
master="$here/build/satest"
python="${PYTHON:-python3}"
[ -x "$master" ] || { echo "Run $here/build.sh first."; exit 2; }
work="$(mktemp -d)"
failed=0
port=20100

run() {
    local name="$1"; shift
    local args=("$@")
    port=$((port + 1))
    "$python" "$repo/outstation.py" --headless --trace --port "$port" --update-key-file "$work/$name.hex" --sa-file "$work/$name.json" "${OUTSTATION_ARGS[@]}" > "$work/$name.outstation.log" 2>&1 &
    local pid=$!
    sleep 1.5
    timeout 60 "$master" "$port" "${args[@]}" > "$work/$name.master.log" 2>&1
    local code=$?
    kill "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    grep -E "^(PASS|FAIL) " "$work/$name.master.log" | sed "s/^/[$name] /"
    [ "$code" -eq 0 ] || { failed=1; echo "[$name] failed, logs in $work"; }
}

user1=$(printf '22%.0s' $(seq 16))
user2=$(printf '33%.0s' $(seq 32))
authority=$(printf '44%.0s' $(seq 32))
printf '{"users": [{"number": 2, "name": "viewer", "role": "Viewer", "key": "%s"}]}\n' "$user2" > "$work/sav5.json"
OUTSTATION_ARGS=(--update-key "$user1" --authority-key "$authority")
run sav5 "$user1" "$user2" "$authority"
for mac in 2 3 4 5; do
    key=$(printf '55%.0s' $(seq 32))
    OUTSTATION_ARGS=(--update-key "$key" --mac "$mac")
    run "mac$mac" "$key"
done
OUTSTATION_ARGS=(--no-auth)
run plain plain
[ "$failed" -eq 0 ] && echo "interop ok" || echo "interop FAILED"
exit "$failed"
