# Pramagent With LangGraph

Pramagent can sit at the boundary where a LangGraph workflow is about to call a
tool. The model can propose a tool name and arguments, but Pramagent checks the
proposal before the side effect runs.

This is the integration pattern linked from the LangChain docs listing for
`ToolGuardLayer`: deterministic policy outside the model, human approval for
high-consequence actions, and audit evidence for each decision.

## Install

```bash
pip install pramagent langgraph langchain
```

For API, dashboard, Postgres, Redis, or encrypted-store pilots, install the
extras you need:

```bash
pip install "pramagent[api,dashboard,postgres,redis,encrypted]"
```

## Guard A LangGraph Tool Call

Use `ToolGuardLayer` to define what a tool is allowed to do. The example below
allows `lookup_customer` for read-only access and requires human approval before
`wire_transfer` can execute.

```python
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from pramagent import Pramagent, Verdict
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect


def lookup_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id, "status": "active"}


def wire_transfer(amount_usd: float, destination: str) -> dict:
    # Real applications should call the payment rail here only after approval.
    return {"sent": amount_usd, "destination": destination}


TOOLS = {
    "lookup_customer": lookup_customer,
    "wire_transfer": wire_transfer,
}

guard = ToolGuardLayer(
    policies=[
        ToolPolicy(
            name="lookup_customer",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            allowed_tenants={"finance"},
            schema={
                "type": "object",
                "required": ["customer_id"],
                "properties": {
                    "customer_id": {"type": "string", "pattern": r"^cust_[0-9]+$"}
                },
                "additionalProperties": False,
            },
        ),
        ToolPolicy(
            name="wire_transfer",
            side_effect=SideEffect.PAYMENT,
            action=Verdict.ESCALATE,
            allowed_tenants={"finance"},
            schema={
                "type": "object",
                "required": ["amount_usd", "destination"],
                "properties": {
                    "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 5000},
                    "destination": {"type": "string", "pattern": r"^acct-[0-9]{6,}$"},
                },
                "additionalProperties": False,
            },
        ),
    ],
    default_verdict=Verdict.BLOCK,
)

armor = Pramagent(tool_guard=guard)


class AgentState(TypedDict, total=False):
    tenant_id: str
    session_id: str
    tool_name: str
    tool_args: dict[str, Any]
    tool_result: Any
    blocked: bool
    approval_required: bool
    pramagent_decision: dict[str, Any]


def guarded_tool_node(state: AgentState) -> AgentState:
    tool_name = state["tool_name"]
    tool_args = state.get("tool_args", {})

    decision = armor.validate_tool(
        tool_name,
        tool_args,
        tenant_id=state.get("tenant_id", "default"),
        session_id=state.get("session_id", "default"),
        action_label=tool_name,
    )

    update: AgentState = {"pramagent_decision": decision.to_dict()}

    if decision.verdict == Verdict.BLOCK:
        update["blocked"] = True
        return update

    if decision.verdict == Verdict.ESCALATE:
        # ESCALATE is not consent. Queue approval, notify a human, or stop here.
        update["approval_required"] = True
        return update

    update["tool_result"] = TOOLS[tool_name](**tool_args)
    return update


builder = StateGraph(AgentState)
builder.add_node("guarded_tool", guarded_tool_node)
builder.set_entry_point("guarded_tool")
builder.add_edge("guarded_tool", END)
graph = builder.compile()

result = graph.invoke(
    {
        "tenant_id": "finance",
        "session_id": "demo-1",
        "tool_name": "wire_transfer",
        "tool_args": {"amount_usd": 250, "destination": "acct-123456"},
    }
)

assert result["approval_required"] is True
```

## Verdict Handling

Treat the verdict as the execution contract:

| Verdict | Meaning in a LangGraph tool node |
|---|---|
| `ALLOW` | Execute the tool and record the decision. |
| `ESCALATE` | Stop before execution and route to human approval. Do not run the tool until approval is recorded. |
| `BLOCK` | Stop before execution. Return or raise a policy failure. |

For durable approval workflows, use Pramagent's persistent HITL queues
(`SQLiteHITLQueue` or `PostgresHITLQueue`) and re-run the side effect only after
the approval record exists. Silence is never approval.

## Prompt/Input Guard Node

Pramagent also ships a small LangGraph node adapter for guarding text before it
reaches later graph nodes:

```python
from langgraph.graph import StateGraph

from pramagent import Pramagent
from pramagent.adapters.langgraph import PramagentNode

armor = Pramagent()

builder = StateGraph(dict)
builder.add_node("pramagent", PramagentNode(armor=armor, input_key="input"))
builder.set_entry_point("pramagent")
```

`PramagentNode` writes `pramagent_trace` into the graph state with the trace id,
hash, verdicts, redactions, HITL status, and block reason. Use this for prompt
and response trust evidence. Use `validate_tool()` for the stricter
pre-execution tool boundary.

## What This Does Not Claim

Pramagent is alpha trust middleware. It is not a sandbox, not an MCP server, and
not a SOC 2/HIPAA certification. It provides deterministic policy checks,
approval gates, PII redaction, and tamper-evident traces that can support a
larger security program.

For a provider-specific example, see the merged
[Google Gemini Cookbook recipe](https://github.com/google-gemini/cookbook/blob/main/examples/Pramagent_trust_layer_for_gemini.ipynb).

## Since The Cookbook Pin

The Gemini Cookbook notebook is pinned to an older `pramagent` release so its
outputs stay reproducible. Keep that notebook frozen. Current projects should
upgrade Pramagent from PyPI before using the newer hook console, tenant
controls, or quantum examples.

The current package keeps the public `Pramagent`, `ToolGuardLayer`,
`ToolPolicy`, `SideEffect`, `Verdict`, and `validate_tool()` surface intact,
then adds optional controls around it:

- Local Claude, Gemini CLI, Codex, and plugin hooks can send proposed tool work
  through the same ToolGuard policy layer.
- The dashboard `/hooks` console lets an admin enable or disable hook surfaces,
  block tools globally, edit ToolGuard JSON policies, and manage per-tenant
  tool permissions from one place.
- Hook configuration changes are written to a SHA-256 hash-chained audit log.
- Quantum examples live under `examples/quantum/` and show guarded PennyLane
  QNode execution with shot and cost accounting, input checks,
  circuit-structure checks, result sanity checks, and replayable fingerprints.

None of these additions require changing the upstream LangChain listing or the
frozen cookbook link. They land here, in the repository those links already send
readers to.
