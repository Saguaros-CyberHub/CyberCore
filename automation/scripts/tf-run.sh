#!/usr/bin/env bash
set -euo pipefail

BASE="/home/cactus-admin/CyberCore/automation/terraform"
TEMPLATE_DIR="$BASE"
RUNS_DIR="$BASE/runs"

# Default action (you can override by env if you ever want)
ACTION="${ACTION:-apply}"

############################################
# Positional arguments from n8n
#  $1 = module_key      (crucible/cyberlabs/forge)
#  $2 = context_id      (lane_id, vm_request_id, etc.)
#  $3 = vxlan_id        (integer)
#  $4 = vm_specs_json   (JSON string)
#  $5 = runtime_minutes (optional)
############################################

MODULE_KEY="${1:?module_key (arg 1) required}"
CONTEXT_ID="${2:?context_id (arg 2) required}"

if [ "$ACTION" = "apply" ]; then
  VXLAN_ID="${3:?vxlan_id (arg 3) required}"
  VM_SPECS_JSON="${4:?vm_specs_json (arg 4) required}"
  RUNTIME_MINUTES="${5:-180}"
fi

RUN_DIR="$RUNS_DIR/$CONTEXT_ID"
mkdir -p "$RUN_DIR"

# Copy template files only once
if [ ! -f "$RUN_DIR/main.tf" ]; then
  cp "$TEMPLATE_DIR/main.tf"      "$RUN_DIR/"
  cp "$TEMPLATE_DIR/providers.tf" "$RUN_DIR/"
  cp "$TEMPLATE_DIR/variables.tf" "$RUN_DIR/"
  cp "$TEMPLATE_DIR/versions.tf"  "$RUN_DIR/"
fi

cd "$RUN_DIR"

terraform init -input=false -upgrade=false

if [ "$ACTION" = "apply" ]; then
  TF_VAR_module_key="$MODULE_KEY" \
  TF_VAR_context_id="$CONTEXT_ID" \
  TF_VAR_vxlan_id="$VXLAN_ID" \
  TF_VAR_vm_specs_json="$VM_SPECS_JSON" \
  TF_VAR_runtime_minutes="$RUNTIME_MINUTES" \
  terraform apply -auto-approve -input=false
else
  TF_VAR_module_key="$MODULE_KEY" \
  TF_VAR_context_id="$CONTEXT_ID" \
  terraform destroy -auto-approve -input=false
fi