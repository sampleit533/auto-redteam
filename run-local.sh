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

echo "Waiting for SSH..."
timeout 30 bash -c 'until nc -z 127.0.0.1 2222; do sleep 1; done'
echo "SSH ready"

echo "Waiting for LocalStack..."
timeout 60 bash -c 'until curl -sf http://localhost:4566/_localstack/health > /dev/null; do sleep 2; done'
echo "LocalStack ready"

# 2. Run simulation
echo ""
echo "[2/5] Running simulation..."
export TARGET_SSH_HOST=localhost
export IAM_ENDPOINT=http://localhost:4566
export REDTEAM_SSH_TEST_PASSWORD="${REDTEAM_SSH_TEST_PASSWORD:-RedteamPass123!}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

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

# 5. Summary
echo ""
echo "[5/5] Done!"
echo "========================================"
echo "  Artifacts:"
echo "    - artifacts/results.json"
echo "    - artifacts/evaluation.json"
echo "    - artifacts/report.html"
echo "========================================"

# Open report if possible
if command -v xdg-open &> /dev/null; then
    xdg-open artifacts/report.html 2>/dev/null || true
elif command -v open &> /dev/null; then
    open artifacts/report.html 2>/dev/null || true
fi
