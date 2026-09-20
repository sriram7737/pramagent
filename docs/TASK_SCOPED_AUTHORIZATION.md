# Task-Scoped Authorization

Pramagent's task controller limits what an agent can execute even when the
model ignores instructions, misunderstands the task, or proposes a persuasive
reason to exceed its authority.

## Contract

`ActionRequest` is an immutable canonical snapshot of:

- the tenant, task, and policy version;
- the exact tool, operation, and arguments;
- resources and destinations;
- spend and affected-record counts;
- expiration and a unique execution ID.

`TaskPermission` is created by trusted application logic. Its operation, tool,
resource, and destination allow-lists are deny-all when empty. It also carries
cumulative action, spend, and affected-record limits, expiration, operations
that require approval, and optional operation-sequence prerequisites.

`SQLiteActionController` persists the permission, reservation, action state,
and result. It serializes reservations before approval or dispatch, binds an
approval to the action digest, revalidates policy immediately before dispatch,
and never automatically retries an outcome whose external effect is unknown.

Stable `DecisionCode` values are for program logic. Human-readable
explanations and `summarize_action()` output are display text only.

## Minimal Example

```python
import time
from pramagent import (
    ActionEffect, ActionRequest, Pramagent,
    SQLiteActionController, TaskPermission,
)
from pramagent.adapters import mediated_tool

token = "load-this-from-a-secret-manager"
controller = SQLiteActionController("actions.db", operator_token=token)
controller.put_permission(TaskPermission(
    task_id="repair-42",
    tenant_id="acme",
    policy_version=1,
    expires_at_us=time.time_ns() // 1_000 + 3_600_000_000,
    allowed_operations=("site.deploy",),
    allowed_tools=("deployer",),
    allowed_resources=("repo:website",),
    allowed_destinations=("env:production",),
    approval_required_operations=("site.deploy",),
    max_actions=1,
    max_affected_records=20,
), token=token)

armor = Pramagent(action_controller=controller)

def make_request(args, kwargs):
    commit = args[0]
    return ActionRequest.create(
        execution_id=kwargs["execution_id"],
        task_id="repair-42",
        tenant_id="acme",
        policy_version=1,
        tool_name="deployer",
        operation="site.deploy",
        arguments={"args": [commit], "kwargs": kwargs},
        resources=("repo:website",),
        destinations=("env:production",),
        affected_records=1,
        effect=ActionEffect.WRITE,
    )

@mediated_tool(
    armor,
    tool_name="deployer",
    request_factory=make_request,
    operator_token=token,
)
def deploy(commit, **kwargs):
    return real_deployment_client.deploy(commit)

pending = deploy("abc123", execution_id="deploy-abc123")
assert pending.state.value == "awaiting_approval"

completed = controller.approve(
    pending.execution_id,
    pending.action_digest,
    reviewer="operator@example.com",
    token=token,
)
```

The model-facing process should receive only the proposal API. It must not
receive the operator token or downstream credentials.

## Execution States

The durable states are `proposed`, `awaiting_approval`, `approved`,
`executing`, `completed`, `failed`, `outcome_unknown`, `denied`, and
`cancelled`.

An exception after dispatch becomes `outcome_unknown`, not `failed`. The same
execution ID will not dispatch again until trusted code reconciles the external
outcome. Controller restart converts an in-flight `executing` record to
`outcome_unknown`.

## Deployment Boundary

The in-process decorator demonstrates the contract but is not an OS security
boundary. For consequential operations:

1. Run the controller and executors as a separately permissioned service.
2. Keep downstream credentials only in that service.
3. Prevent the agent identity from calling protected systems directly.
4. Protect the controller database, policy administration, audit keys, and
   operator authentication from the agent OS identity.
5. Use a shared transactional backend before running multiple controller
   hosts. The included SQLite controller is a single-host implementation.

The controller enforces configured facts. It does not decide whether arbitrary
natural-language actions are necessary, and deterministic summaries do not
make an unauthorized action permissible.

## Verification

`tests/test_action_control.py` covers exact-argument binding, tenant and
resource scope, concurrent cumulative reservations, policy rotation,
expiration, approval mismatch, cancellation, sequence rules, restart,
idempotency, uncertain outcomes, and adapter behavior.

`examples/bank_baseline/` is an offline synthetic reference workflow. It uses
no real money and is not a production banking integration.
