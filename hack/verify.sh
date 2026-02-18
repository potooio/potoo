#!/usr/bin/env bash
# hack/verify.sh — Verify task completion
#
# Usage:
#   hack/verify.sh all         # Run all checks
#   hack/verify.sh phase0      # Check Phase 0 tasks
#   hack/verify.sh phase1      # Check Phase 1 tasks
#   hack/verify.sh task 0.2    # Check specific task

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

check() {
    local task="$1"
    local desc="$2"
    local cmd="$3"

    printf "  %-10s %-50s " "$task" "$desc"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAIL${NC}"
        ((FAIL++))
    fi
}

phase0() {
    echo "=== Phase 0: Scaffolding ==="
    check "TASK-0.1" "Go module initializes cleanly" \
        "go mod tidy && go build ./..."
    check "TASK-0.2" "Util helpers pass tests" \
        "go test ./internal/util/ -count=1"
    check "TASK-0.3" "DeepCopy + CRD manifests exist" \
        "test -f api/v1alpha1/zz_generated.deepcopy.go && ls config/crd/*.yaml | wc -l | grep -qE '[3-9]'"
    check "TASK-0.4" "Controller binary compiles" \
        "go build ./cmd/controller/"
    check "TASK-0.5" "golangci-lint config exists" \
        "test -f .golangci.yml"
    check "TASK-0.6" "Makefile verify targets exist" \
        "grep -q 'verify-phase-0' Makefile"
}

phase1() {
    echo "=== Phase 1: Core Discovery + Native Adapters ==="
    check "TASK-1.1" "Indexer tests pass" \
        "go test ./internal/indexer/ -count=1"
    check "TASK-1.2" "NetworkPolicy adapter tests pass" \
        "go test ./internal/adapters/networkpolicy/ -count=1"
    check "TASK-1.3" "ResourceQuota adapter tests pass" \
        "go test ./internal/adapters/resourcequota/ -count=1"
    check "TASK-1.4" "LimitRange adapter tests pass" \
        "go test ./internal/adapters/limitrange/ -count=1"
    check "TASK-1.5" "Webhook adapter tests pass" \
        "go test ./internal/adapters/webhookconfig/ -count=1"
    check "TASK-1.6" "Generic adapter tests pass" \
        "go test ./internal/adapters/generic/ -count=1"
    check "TASK-1.7" "Discovery engine tests pass" \
        "go test ./internal/discovery/ -count=1"
    check "TASK-1.8" "Correlator tests pass" \
        "go test ./internal/correlator/ -count=1"
    check "TASK-1.9" "Notifier tests pass" \
        "go test ./internal/notifier/ -count=1"
    check "TASK-1.10" "Main compiles with all wiring" \
        "go build ./cmd/controller/"
    check "TASK-1.11" "All unit tests pass" \
        "go test ./internal/... -count=1"
}

phase1_5() {
    echo "=== Phase 1.5: Agent-Consumable Outputs ==="
    check "TASK-1.5.1" "Structured Event annotations" \
        "go test ./internal/notifier/ -count=1 -run TestEventBuilder"
    check "TASK-1.5.2" "Workload annotation updater" \
        "go test ./internal/notifier/ -count=1 -run TestWorkloadAnnotator"
    check "TASK-1.5.3" "MachineReadable ConstraintReport" \
        "go test ./internal/notifier/ -count=1 -run TestReportReconciler_MachineReadable"
    check "TASK-1.5.4" "Remediation builder" \
        "go test ./internal/notifier/ -count=1 -run TestRemediation"
    check "TASK-1.5.5" "MCP server" \
        "go test ./internal/mcp/ -count=1"
    check "TASK-1.5.6" "kubectl plugin compiles" \
        "go build ./cmd/kubectl-sentinel/"
    check "TASK-1.5.7" "Capabilities endpoint" \
        "go test ./internal/api/ -count=1"
}

summary() {
    echo ""
    echo "=== Summary ==="
    echo -e "  ${GREEN}Passed: $PASS${NC}"
    echo -e "  ${RED}Failed: $FAIL${NC}"
    if [ $FAIL -eq 0 ]; then
        echo -e "  ${GREEN}All checks passed!${NC}"
    else
        echo -e "  ${YELLOW}$FAIL check(s) need work.${NC}"
        exit 1
    fi
}

case "${1:-all}" in
    all)
        phase0
        phase1
        phase1_5
        summary
        ;;
    phase0)
        phase0
        summary
        ;;
    phase1)
        phase1
        summary
        ;;
    phase1.5|phase1_5)
        phase1_5
        summary
        ;;
    task)
        TASK_ID="${2:-}"
        if [ -z "$TASK_ID" ]; then
            echo "Usage: hack/verify.sh task <ID> (e.g., hack/verify.sh task 0.2)"
            exit 1
        fi
        # Extract and run the verify command for a specific task from TASKS.md
        VERIFY_CMD=$(grep -A5 "TASK-${TASK_ID}" TASKS.md | grep "verify:" | head -1 | sed 's/.*verify: `\(.*\)`/\1/')
        if [ -z "$VERIFY_CMD" ]; then
            echo "Task TASK-${TASK_ID} not found or has no verify command"
            exit 1
        fi
        echo "Running: $VERIFY_CMD"
        eval "$VERIFY_CMD"
        ;;
    *)
        echo "Usage: hack/verify.sh [all|phase0|phase1|task <ID>]"
        exit 1
        ;;
esac
