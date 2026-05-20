#!/bin/bash
set -e

cd "$(dirname "$0")"

# Activate venv if exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

MODE="${1:-safe}"
SCENARIO="${2:-all}"
RUN_ID="local-$(date +%Y%m%d-%H%M%S)"

echo "========================================"
echo "  RedTeam Local Pipeline"
echo "  Mode: $MODE | Scenario: $SCENARIO"
echo "  Run ID: $RUN_ID"
echo "========================================"

# Cleanup function
cleanup() {
    echo ""
    echo "[TEARDOWN] Stopping containers..."
    docker compose -f targets/docker-compose.yml down -v 2>/dev/null || true
}
trap cleanup EXIT

# 1. Start targets
echo ""
echo "[1/5] Starting sandbox targets..."
docker compose -f targets/docker-compose.yml up -d --build

echo "Waiting for SSH (target-ssh:2222)..."
timeout 30 bash -c 'until nc -z 127.0.0.1 2222; do sleep 1; done'
echo "SSH ready"

echo "Waiting for LocalStack (4566)..."
timeout 120 bash -c 'until curl -sf http://localhost:4566/_localstack/health > /dev/null; do sleep 2; done'
echo "LocalStack ready"

echo "Waiting for target-web (8080)..."
timeout 30 bash -c 'until nc -z 127.0.0.1 8080; do sleep 1; done' || echo "WARNING: target-web not ready"

echo "Waiting for target-redis (6379)..."
timeout 30 bash -c 'until nc -z 127.0.0.1 6379; do sleep 1; done' || echo "WARNING: target-redis not ready"

# 2. Run simulation
echo ""
echo "[2/5] Running simulation..."
export TARGET_SSH_HOST=localhost
export IAM_ENDPOINT=http://localhost:4566
export TARGET_USE_LOCALHOST=1
export REDTEAM_SSH_TEST_PASSWORD="${REDTEAM_SSH_TEST_PASSWORD:-RedteamPass123!}"
export REDTEAM_IAM_PRINCIPAL="${REDTEAM_IAM_PRINCIPAL:-local-runner-${RUN_ID}}"
export REDTEAM_CI_ACTOR="${REDTEAM_CI_ACTOR:-local-actor-${RUN_ID}}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# Pcap capture for T3/T6/T7 — runs tcpdump inside an ephemeral docker
# container with cap_net_raw (no host setcap, no sudo).
export ENABLE_PCAP="${ENABLE_PCAP:-1}"
if [ "${ENABLE_PCAP}" = "1" ]; then
    echo "[PCAP] Building recorder image (one-time, ~5s on first run)..."
    docker build -q -t redteam/pcap-recorder:latest targets/pcap-recorder/ \
        && echo "[PCAP] Recorder image ready" \
        || { echo "[PCAP] WARNING: build failed, disabling capture"; export ENABLE_PCAP=0; }

    echo "[SNORT] Building Snort 3 replay image (one-time, ~10s on first run)..."
    docker build -q -t redteam/snort-runner:latest targets/snort-runner/ \
        && echo "[SNORT] Snort runner image ready" \
        || echo "[SNORT] WARNING: build failed, T7 will skip Snort replay"
fi

python runners/simulate.py \
    --scenario "$SCENARIO" \
    --mode "$MODE" \
    --run-id "$RUN_ID" \
    --output artifacts/results.json

# 3. Evaluate
echo ""
echo "[3/5] Evaluating detections..."
python evaluation/evaluate_results.py \
    --results artifacts/results.json \
    --mappings evaluation/expected_mappings.yaml \
    --out artifacts/evaluation.json || true

# 4. Generate report
echo ""
echo "[4/5] Generating report..."
if [ ! -f artifacts/evaluation.json ]; then
    python reporting/make_eval_stub.py
fi
python reporting/generate_report.py \
    --evaluation artifacts/evaluation.json \
    --template reporting/templates/report.html.j2 \
    --out artifacts/report.html || true

# Multi-run trend dashboard (reads artifacts/history/*.json populated by evaluator)
python reporting/generate_trends.py \
    --history artifacts/history \
    --template reporting/templates/trends.html.j2 \
    --out artifacts/trends.html || true

# Baseline regression check (informational locally — never blocks)
echo ""
echo "[4b/5] Baseline regression check..."
python evaluation/check_baseline.py || true

# Export Sigma rules from internal mappings
echo ""
echo "[4c/5] Exporting Sigma rules..."
python evaluation/export_sigma.py --out-dir sigma || true

# 5. Summary
echo ""
echo "[5/5] Done!"
echo "========================================"
echo "  Artifacts:"
echo "    - artifacts/results.json"
echo "    - artifacts/evaluation.json"
echo "    - artifacts/report.html"
echo "    - artifacts/trends.html"
if ls artifacts/*.pcap >/dev/null 2>&1; then
    for p in artifacts/*.pcap; do
        echo "    - $p"
    done
fi
if ls artifacts/*.snort.txt >/dev/null 2>&1; then
    for s in artifacts/*.snort.txt; do
        echo "    - $s  ($(wc -l < "$s") snort alert line(s))"
    done
fi
echo "    - artifacts/history/  ($(ls artifacts/history/*.json 2>/dev/null | wc -l) run(s) recorded)"
echo "    - sigma/  ($(ls sigma/*.yml 2>/dev/null | wc -l) Sigma rule(s))"
echo "========================================"

# Open report if possible (non-blocking — won't hang on headless systems).
# Skip when DISPLAY is unset or we're inside CI; spawn detached via setsid+nohup.
if [ -z "${CI:-}" ] && [ -n "${DISPLAY:-}" ]; then
    if command -v xdg-open >/dev/null 2>&1; then
        setsid -f bash -c "xdg-open artifacts/report.html >/dev/null 2>&1" </dev/null || true
    elif command -v open >/dev/null 2>&1; then
        setsid -f bash -c "open artifacts/report.html >/dev/null 2>&1" </dev/null || true
    fi
fi
