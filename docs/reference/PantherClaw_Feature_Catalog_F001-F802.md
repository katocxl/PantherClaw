# PantherClaw — Complete Features List

> **Reference document — requirements traceability source (F001–F802, SG01–SG14).** It defines desired product behavior, not implementation. The authoritative build guidance is [`docs/BUILD_GUIDE.md`](../BUILD_GUIDE.md); architecture, protocol and security rules in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md), [`docs/protocol/PAP-1.md`](../protocol/PAP-1.md) and [`docs/security/`](../security/) take precedence where they are more specific. Licensed under the repository [LICENSE](../../LICENSE).

**Source:** [PantherClaw_Product_Specification.md](PantherClaw_Product_Specification.md), version 2.1, October 7, 2026; required companion [GATES_AND_REVIEW.md](../security/GATES_AND_REVIEW.md) (formerly the secure engineering plan, version 1.0).  
**Product:** PantherClaw (formerly the working name "AgentGate"), an AI agent identity and runtime authorization firewall.  
**Status:** Full intended product scope. These are proposed capabilities and required behaviors, not claims that the product is implemented or production-ready.  
**Catalog:** 802 numbered product feature requirements in 61 groups, covering product sections 1–43. Appendix A indexes 14 separate engineering requirements added by source §44 and the companion plan. Numbered entries include functions, controls, states, quality requirements, and explicit product boundaries.

This catalog converts the description into concrete features and preserves the functionality, restrictions, states, workflows, and evidence requirements attached to them. Repeated requirements are consolidated; scenarios are translated into reusable functionality. Source-section references identify where each feature group comes from. No product release order or concrete implementation architecture is assumed. Appendix A explicitly adds the supplied screenshots' secure development guidance as engineering obligations; it does not renumber or expand the 802 product features.

## Contents

- [Workspace, identity, and authority](#workspace-identity-and-authority)
- [Runtime controls and human decisions](#runtime-controls-and-human-decisions)
- [Policy authoring and rollout](#policy-authoring-and-rollout)
- [Operations, investigations, and exposure](#operations-investigations-and-exposure)
- [Graphs, search, and onboarding](#graphs-search-and-onboarding)
- [Connections, tool meaning, and coverage](#connections-tool-meaning-and-coverage)
- [Transactions, verification, and evidence](#transactions-verification-and-evidence)
- [Response, governance, and operational behavior](#response-governance-and-operational-behavior)
- [Governed automations](#governed-automations)
- [Supported work, quality measures, and boundaries](#supported-work-quality-measures-and-boundaries)
- [Source coverage map](#source-coverage-map)
- [Appendix A — Secure engineering requirements](#appendix-a--secure-engineering-requirements)

## Workspace, identity, and authority

### 01. Unified product workspace

*Source: §§1–8, 20, 29, 36–37.*

- **F001 — Seven primary work surfaces:** Operations, Agents, Policies, Approvals, Investigations, Connections, and Automations, with universal search available throughout.
- **F002 — Operations-integrated posture:** Present ongoing exposure reduction as a view within Operations, with organization settings outside daily work.
- **F003 — Shared product records:** Manage Agents, Runs, Resources, Grants, Policies, and Actions as primary objects; attach people, services, tools, connections, approvals, incidents, automations, teams, environments, definitions, consequences, coverage, and receipts to them.
- **F004 — Logical transaction record:** Keep one action's exact request, authority, decision, human requirements, attempts, and effects together; a run can contain many transactions, and retries do not automatically become new permission.
- **F005 — Consistent evidence across surfaces:** Opening the same action from any page displays the same underlying transaction and supporting records.
- **F006 — Role-oriented saved views:** Give developers, SOC analysts, security engineers, IAM engineers, platform engineers, CISOs, auditors, and business approvers views suited to their jobs without creating competing versions of the records.
- **F007 — Pinned task entry points:** Let users pin Work, Protect, Configure, Operations, and Audit entry points over existing records without changing permissions.
- **F008 — Direct workbench access:** Make coverage, tool meaning, and evidence directly accessible within the relevant surfaces.
- **F009 — Visible working scope:** Keep organization, team, environment, and time range visible during inspection and action.
- **F010 — Context-preserving navigation:** Open details without losing filters, selection, or time range; preserve selection during live updates.
- **F011 — Stable review experience:** Keep the item under the cursor stable and avoid reordering approvals during review; group related updates.
- **F012 — Accessible controls:** Support keyboard operation and accessible status text; convey graph and control meaning in text as well as color or styling.
- **F013 — Consequence previews:** Before destructive commitments, show target count, scope, and consequence.
- **F014 — Plain-language terminology:** Use terms such as task grant, action definition, reviewed tool package, downstream consequence, protection boundary, coverage evidence, and transaction evidence; expose formal identifiers in advanced evidence views.

### 02. Agent inventory and lifecycle

*Source: §§8–9, 18, 21, 26, 38.*

- **F015 — Agent discovery:** Detect evidence of agent activity and place new discoveries in an unclaimed queue.
- **F016 — Accountable ownership:** Record organization, owning team, accountable owner, and backup owner; support explicit ownership claiming.
- **F017 — Agent purpose and environment:** Show the agent's permitted purpose, environment, and connected execution context.
- **F018 — Agent detail summary:** Answer who owns the agent, its permitted purpose, active authority, protected paths, and outstanding issues.
- **F019 — Agent detail tabs:** Provide Runs, Authority, Resources, Changes, and Evidence views.
- **F020 — Agent lifecycle states:** Distinguish Discovered, Claimed, Verified, Observed, Partially protected, Protected within scope, Suspended, and Retired, with an appropriate next action for each.
- **F021 — Scope-qualified protection:** Label an agent protected only for named paths with current evidence; explicitly label mixed protected and unprotected paths as partially protected.
- **F022 — Inventory actions:** Test identity, inspect access, tighten grants, suspend agents, and retire them.
- **F023 — Agent retirement:** Disable new runs while preserving history and making residual-access review available.
- **F024 — Explicit change history:** Record ownership, identity, authority, and coverage changes rather than silently altering the current summary.
- **F025 — Automation actor visibility:** Include automation execution identities in agent inventory and exposure views; avoid invisible administrator identities.

### 03. Verified identity and actor attribution

*Source: §§1, 7, 9–10, 12, 16, 26, 39.*

- **F026 — Stable agent identity:** Maintain accountable continuity for ownership and history while giving each run its own identity context and grants.
- **F027 — Separate launcher and principal:** Distinguish the human or service starting a run from the represented principal whose authority it uses.
- **F028 — Release and configuration identity:** Record verifiable agent release or configuration identity.
- **F029 — Workload-instance verification:** Identify the actual workload instance and its verification basis separately from the named agent definition.
- **F030 — Application and executor attribution:** Distinguish calling application and execution actor when they differ from the agent.
- **F031 — Verification metadata:** Show verification method, last verification, required trust level, and unresolved identity ambiguity.
- **F032 — Evidence-based identity:** Require verification beyond a model name, display name, or self-reported identifier.
- **F033 — Identity drift reassessment:** Reassess affected capabilities after release, schema, execution-context, or other material identity changes.
- **F034 — No name-based authority inheritance:** Prevent sensitive authority from silently transferring to a different actor with the same name.
- **F035 — Ambiguous identity resolution:** Keep ambiguous actors separate until an authorized user resolves them with evidence; retain historical identity changes.
- **F036 — Human identity reuse:** Use existing trusted human identity systems rather than replacing them.
- **F037 — Current identity checks:** Verify the required agent instance, application, launcher, represented principal, executor, and approver at the point where their authority is used.

### 04. Task grants and effective authority

*Source: §§1, 5, 10–12, 26, 38–39.*

- **F038 — Task-specific grants:** Delegate bounded authority for a particular run and task rather than relying on broad standing access.
- **F039 — Grant provenance:** Record the grantor and the authority that permits that grantor to delegate.
- **F040 — Grant subjects:** Bind the grant to an agent and represented principal.
- **F041 — Grant resource scope:** Identify the approved task, stable resources, and permitted target set.
- **F042 — Operation and parameter boundaries:** Specify permitted operations, parameter constraints, data destinations, amounts, and other material limits.
- **F043 — Grant budgets and gates:** Record total budgets and required approvals.
- **F044 — Grant validity:** Record environment, validity period, revisions, expiry, and revocation state.
- **F045 — Delegation settings:** Record whether delegation is permitted and the remaining delegation depth.
- **F046 — Effective-authority comparison:** Distinguish what the grantor could delegate, what was actually delegated, organizational restrictions, and authority currently usable by the run.
- **F047 — Intersection of authority:** Restrict usable authority by the grant, principal scope, resource restrictions, organization controls, and current containment state; a local allow cannot defeat a stronger prohibition.
- **F048 — Credential-overreach findings:** Show technical credential reach beyond the task grant as exposure, not extra permission.
- **F049 — Trusted task context:** Establish task-linked IDs, permitted operations, budgets, destinations, expiry, and delegation from trusted sources.
- **F050 — Agent-context labeling:** Let an agent provide explanatory context without permitting it to enlarge authority.
- **F051 — Scope-mismatch analysis:** Flag semantic mismatch for review without creating rights or overriding explicit prohibitions.
- **F052 — Authorized grant correction:** Route legitimate missing-resource or scope corrections through the authorized owner rather than disabling guardrails.
- **F053 — Expiry and task-close handling:** Stop new authority at grant expiry or task closure under approved lifecycle controls; extensions require fresh authorized review.
- **F054 — No agent self-authorization:** Agents cannot create, expand, approve, or attest their own authority; approved automated grant issuance is separately governed.

### 05. Child agents and authority lineage

*Source: §§7, 12, 17, 19, 25, 31, 38, 43.*

- **F055 — Separate creation and delegation:** Treat creating a child agent and granting that child authority as distinct actions.
- **F056 — Explicit delegation permission:** Deny delegation unless the parent grant explicitly permits it.
- **F057 — Non-expanding child scope:** Give a child equal or narrower authority; do not let it inherit additional operations such as a parent's merge permission.
- **F058 — Child expiry ceiling:** Prevent child authority from outliving the parent grant.
- **F059 — Shared task budgets:** Keep cumulative budgets shared across parent, children, and related runs unless authorized allocation explicitly establishes separate limits.
- **F060 — Dependent revocation:** Parent revocation invalidates dependent child authority for new covered actions.
- **F061 — Independent child accountability:** Give children their own identities, grants, and visible attribution.
- **F062 — Readable authority lineage:** Trace an action through original authorizer, grant issuance, delegation, applicable policy restrictions, and the current boundary.
- **F063 — Lineage drill-down:** Show scope, issuer, evidence, time, expiry, and revocation dependencies at each step.
- **F064 — Scheduler attribution:** Preserve the difference between a scheduling launcher and the business principal providing authority.
- **F065 — Child-run navigation:** Link parent and child runs in run inspection, investigation, timelines, and exposure graphs.

## Runtime controls and human decisions

### 06. Action cards and decision explanations

*Source: §§1, 8, 10, 14, 19–21, 34, 37.*

- **F066 — Human-readable action card:** Show what the agent wants to do, the target, material value or data, represented principal, task, environment, decision, reason, grant constraints, expiry, and execution state.
- **F067 — Expandable request detail:** Expose parameters, stable resource identity, sensitivity, current constraints, rule versions, and contextual-fact provenance.
- **F068 — Secret-safe normal displays:** Remove secrets from ordinary views and separately audit authorized restricted evidence access.
- **F069 — Five readable decision presentations:** Present Allow, Constrain, Hold, Deny, and Cannot authorize while retaining exact underlying decisions.
- **F070 — Precise decision vocabulary:** Preserve `ALLOW`, `ALLOW_WITH_OBLIGATIONS`, `REQUIRE_APPROVAL`, `REQUIRE_STEP_UP`, `DENY`, and `CANNOT_AUTHORIZE` in action records.
- **F071 — Separate approval and authentication:** An action may need both business approval and stronger authentication; completing one does not satisfy the other.
- **F072 — Explicit obligation tracking:** List every required constraint and whether it applies before execution, after dispatch, or before dependent work.
- **F073 — Single-use allowance:** Support allow-once as a bounded, single-use authorization.
- **F074 — Read-only boundaries:** Express read-only scope as an enforceable action boundary.
- **F075 — Warning annotations:** Allow warnings as annotations without substituting them for mandatory blocking.
- **F076 — Unsupported requirement handling:** Return Cannot authorize when a required constraint, approval, custody, or verification obligation cannot be satisfied.
- **F077 — Separate response controls:** Show quarantine, suspension, and termination as response actions rather than authorization decisions.
- **F078 — Decision checklist:** Show passed, failed, missing, and not-applicable conditions, placing the decisive condition first.
- **F079 — Exact failed-condition explanation:** Identify the specific boundary and offending parameter with a permitted alternative or exception path.
- **F080 — Time-specific evidence:** Retain the policy, authority, facts, and other evidence used at decision time.

### 07. Runtime evaluation and final authorization

*Source: §§5, 10, 16, 23, 28, 39–43.*

- **F081 — Coverage-first evaluation:** Establish the workload, target, effect, routes, and current evidence the product can govern.
- **F082 — Identity and containment evaluation:** Verify required actors and check suspension of actors, grants, connections, resources, and tool packages.
- **F083 — Authority evaluation:** Require a valid, sufficiently narrow grant covering the task and target.
- **F084 — Exact action interpretation:** Resolve the reviewed operation, stable resource, material parameters, and supported consequences.
- **F085 — Current-fact checks:** Require present and fresh target facts, classifications, and history.
- **F086 — Boundary checks:** Evaluate prohibitions, permits, sequences, windows, cumulative limits, and current containment.
- **F087 — Requirement checks:** Evaluate approval, stronger authentication, enforceable constraints, access custody, and verification support.
- **F088 — Final binding check:** Immediately before consequential execution, verify that actor, effective action, target, consent, facts, budgets, grant, policy, and access mode still match.
- **F089 — Dispatch and effect observation:** After final authorization, record dispatch, target acceptance, and supported effect evidence separately.
- **F090 — Uncontrolled-action labeling:** Label actions outside coverage as uncontrolled/observed rather than fabricating an allow or deny.
- **F091 — Attempt-versus-boundary status:** Show a blocked attempt alongside partial overall coverage when another equivalent route remains unresolved.
- **F092 — Explicit-prohibition precedence:** Applicable prohibitions deny; local approvals and allows cannot defeat non-overridable controls.
- **F093 — Tightest-limit composition:** Intersect applicable limits and retain all material restrictions.
- **F094 — Combined approval requirements:** Combine compatible requirements; deny conflicting or unsatisfiable requirements with the exact conflict.
- **F095 — No-grant denial:** Deny covered actions without an applicable grant.
- **F096 — Missing-evidence distinction:** Use Cannot authorize for missing required evidence rather than pretending the action is prohibited by business policy.
- **F097 — Bounded evidence recovery:** Permit an explicitly configured wait for required evidence only within a deadline; no consequential dispatch while it is missing.
- **F098 — Observe-only decisions:** Report hypothetical policy results without claiming execution was prevented.
- **F099 — Equivalent-effect consistency:** Apply the same decision to equivalent reviewed effects and facts across tools and channels.

### 08. Safe constraints and transformations

*Source: §§10, 23, 39–40.*

- **F100 — Tool-declared constraint support:** Declare which tools can enforce row limits, selected fields, destinations, target sets, and amounts.
- **F101 — Scoped field filtering:** Return only authorized fields when the integration reliably supports field filtering.
- **F102 — Task-linked record filtering:** Constrain exports to records linked to the approved task where supported.
- **F103 — Supported response redaction:** Redact returned data only where the connection can reliably govern the response.
- **F104 — Semantically safe transformation:** Automatically modify a request only when the tool contract declares the transformation safe and the grant permits it.
- **F105 — Business-action preservation:** Require a revised request for a material change such as reducing an $85 refund to $50; do not silently substitute another business action.
- **F106 — No guessed shell rewriting:** Avoid transforming destructive shell commands by guessing intent; use explicit approved alternatives.
- **F107 — Requested-versus-effective comparison:** Display every permitted modification and its resulting action.
- **F108 — Consent on effective action:** Bind final consent to all material fields after constraints; renew approval after material transformation unless the original consent explicitly authorized that exact transformation and scope.
- **F109 — Opaque-tool limits:** Do not claim unsupported filtering, transformations, or unknown-side-effect control for opaque tools.

### 09. Cumulative budgets and reservations

*Source: §§10–12, 38–39, 42–43.*

- **F110 — Total-value limits:** Limit value across a run, task, or defined period in addition to per-call amounts.
- **F111 — Count limits:** Bound writes, recipients, records, delegations, and operations such as one merge per task.
- **F112 — Rate and concurrency limits:** Bound action rate and maximum concurrent outstanding actions.
- **F113 — Budget-state display:** Show available, reserved, spent, and unresolved allocations.
- **F114 — Concurrent reservation safety:** Prevent simultaneous actions from each consuming the same remaining allowance.
- **F115 — Unknown-outcome reservations:** Retain unresolved payment or action reservations until reconciliation establishes the outcome.
- **F116 — Explicit limit grouping:** Define whether a limit applies to task, principal, target account, team, or another approved grouping.
- **F117 — Cross-run budget enforcement:** Prevent split requests, new run IDs, or child grants from escaping shared limits.
- **F118 — Pre-dispatch reservation:** Reserve required value or action allowances before consequential execution.
- **F119 — Budget evidence in review:** Show total task exposure and remaining allocation in approval, run, and automation detail.

### 10. History, sequence, and timing controls

*Source: §§10, 16, 38, 40, 42–43.*

- **F120 — Recent-change review gates:** Require independent review for a supplier transfer after bank-detail changes within a defined review window.
- **F121 — Single-operation sequence rules:** Permit no more than the approved number of protected operations per task.
- **F122 — Verified prerequisite rules:** Require evidence such as a verified backup before supported destructive maintenance.
- **F123 — Read-to-disclosure controls:** Hold external disclosure after sensitive reads unless a reviewed task permits that data flow.
- **F124 — Defined history semantics:** State whether sequence evidence counts attempts, provider acceptance, confirmed effects, or another explicitly named event.
- **F125 — History explanation:** Show relevant prior transactions, time windows, and evidence freshness.
- **F126 — Trusted historical facts:** Do not treat model memory or agent-authored summaries as proof of history; missing required history is Cannot authorize.
- **F127 — Pre-execution gates:** Complete identity, grant, approval, authentication, budget, supported constraints, custody, and verification-capability checks before work proceeds.
- **F128 — Post-dispatch obligations:** Observe effects and reconcile ambiguity after dispatch.
- **F129 — Dependent-work gates:** Start dependent steps only when the required qualifying effect state is established.
- **F130 — No retroactive permission:** Post-action verification cannot authorize an earlier prohibited action.

### 11. Retries, changed requests, and in-flight work

*Source: §§10, 16, 25, 28, 38–39, 42.*

- **F131 — Stable irreversible-action identity:** Retain the original logical action identity on retries where supported, or reconcile before another attempt.
- **F132 — Changed-request reauthorization:** Require a new decision after changes to parameters, payee, destination, target, represented user, or task.
- **F133 — Approval-expiry enforcement:** Prevent expired approval from authorizing later execution.
- **F134 — Revocation effects:** Block new covered actions and invalidate waiting approvals after applicable revocation.
- **F135 — In-flight cancellation visibility:** Show actual supported cancellation capability, request, confirmation, and unresolved status for dispatched work.
- **F136 — Reconciliation before irreversible retry:** Do not automatically retry unknown payments, deletions, transfers, or external sends.
- **F137 — Current-authority retry checks:** Reassess retry scope, permission, and prerequisites even after evidence confirms no effect occurred.
- **F138 — Preserved original history:** Keep prior dispatch, response, consent, and effects visible through retry, recovery, and compensation.

### 12. Exact approvals and stronger authentication

*Source: §§8, 10, 16, 26, 38–40, 43.*

- **F139 — Consequence-first approval detail:** Begin with the exact action and business consequence rather than a generic approve/reject prompt.
- **F140 — Full approval scope:** Show target, operation, parameters, destination, affected data or transferred value, task, principal, and agent.
- **F141 — Approval basis:** Explain the requirement and approver eligibility; retain grant constraints and supporting business evidence.
- **F142 — Approval context:** Show prior similar approvals as context without treating them as permission precedent.
- **F143 — Approval validity:** Show expiry, single-use scope, current validity, reversibility, and uncertain consequences.
- **F144 — Approve exact action:** Satisfy the specific approval condition without granting broader future access.
- **F145 — Decline with reason:** Record a useful reason and safer alternative where appropriate.
- **F146 — Request more evidence:** Keep the action held only until an explicit deadline.
- **F147 — Propose a narrower action:** Create a revised request with its own decision and approval; original consent does not transfer.
- **F148 — No routine bulk privilege expansion:** Keep permanent policy widening and approve-all-similar behavior outside ordinary action approvals.
- **F149 — Current approver verification:** Recheck identity, current role, business authority, and eligibility at decision and consumption time where required.
- **F150 — Step-up authentication:** Require stronger authentication for configured high-consequence actions, separately from business approval.
- **F151 — Independent approval:** Prevent an initiator from satisfying a requirement for independent review.
- **F152 — Two-person approval:** Require two distinct eligible humans; one response cannot satisfy both approvals.
- **F153 — Role-removal invalidation:** Invalidate unconsumed approval after role removal when current eligibility is required.
- **F154 — Material-change invalidation:** Invalidate approval when relevant target, amount, destination, task, grant, parameters, or other bound conditions change.
- **F155 — Pre-execution revalidation:** Recheck current authority, policy, resource conditions, and approval; return Hold, Deny, or Cannot authorize with the reason when invalid.
- **F156 — Exact consent binding:** Bind stable target IDs, material parameters, effective constraints, relevant prior changes, required target conditions, and policy/grant/tool-meaning revisions.
- **F157 — Stable-target presentation:** Show readable names beside stable identifiers so renaming cannot disguise a changed account or target.
- **F158 — Repository merge review:** Show repository, PR, source commit, destination branch, change summary, required checks, and supported deployment consequences.
- **F159 — Target-condition assurance limits:** Disclose when the target cannot guarantee a condition through execution; a recent read alone does not prove exact-state stability.
- **F160 — Consent history retention:** Preserve original consent even when it can no longer authorize execution.

### 13. Approval channels, routing, and workload management

*Source: §§16, 23, 27–28, 38.*

- **F161 — Cross-channel approval presentation:** Surface the same request in Slack, Teams, ticketing, CLI, IDE, and customer applications where integrated.
- **F162 — Authoritative in-product approval:** Use authenticated product approval as the default authority event.
- **F163 — Equivalent external approval assurance:** Accept external approval only with equivalent identity verification, transaction binding, expiry, and replay resistance; otherwise provide a secure link.
- **F164 — Minimum-data external cards:** Limit channel content and open sensitive or high-consequence requests in verified product detail.
- **F165 — One shared request state:** Share state and recorded responses across channels without duplicating authorization.
- **F166 — No text-inferred approval:** Do not approve sensitive actions from reactions, ambiguous replies, or unverified message text.
- **F167 — Delivery-failure hold:** Keep failed-delivery approvals held until deadline and then expire; failure never counts as approval.
- **F168 — Eligible-approver routing:** Route to current eligible approvers with reminders and escalation inside the approved deadline.
- **F169 — Approval-demand estimation:** Estimate queue demand during policy and automation simulation.
- **F170 — Approval-overload reduction:** Support narrowing rules or substituting safe automatic boundaries when proposed controls would create excessive human gates.
- **F171 — Scoped batch review:** Permit batch review only for demonstrably homogeneous low-risk requests, retaining individual scope and audit records; review destructive and high-value requests individually.

## Policy authoring and rollout

### 14. Task templates and policy editor

*Source: §§8, 10–11, 21–23, 26.*

- **F172 — Protect-a-task entry point:** Start policy creation from the work being protected rather than an unexplained rule form.
- **F173 — Customer support template:** Provide scoped reads and limited updates.
- **F174 — Refund template:** Define amount, payee, and cumulative limits.
- **F175 — Production diagnostics template:** Provide read-only boundaries and approved destinations.
- **F176 — Release deployment template:** Define exact project, release, time window, and approver.
- **F177 — Internal analysis template:** Define classified-data and output restrictions.
- **F178 — Template coverage disclosure:** Explain protection, exclusions, and required connections for each template.
- **F179 — Sentence-based structured rules:** Present readable rules backed by validated structured fields.
- **F180 — Editable policy clauses:** Cover subjects, environments, task types, resources, operations, parameters, sensitivity, destinations, windows, budgets, evidence, authentication, approvals, and decision/response behavior.
- **F181 — Natural-language policy drafting:** Generate drafts with explicit ambiguity; require terms such as large refunds to become concrete thresholds before publication.
- **F182 — Advanced policy representation:** Provide validated advanced editing of the same rule with a human-readable explanation.
- **F183 — Inherited-rule visibility:** Show organizational and other inherited controls, their owner, and the route for requesting change.
- **F184 — Draft-first editing:** Editing creates a draft; saving does not incidentally publish it.

### 15. Suggestions, tests, and simulation

*Source: §§11, 18, 19, 30, 34, 36, 38, 40.*

- **F185 — Evidence-backed policy suggestions:** Include evidence window, coverage limits, observed operations, exceptions, proposed restriction, expected effect, affected agents, and owners.
- **F186 — Suggestion uncertainty:** Show false-positive uncertainty and legitimate needs that may be unobserved; unused authority supports review rather than proving it unnecessary.
- **F187 — Historical decision simulation:** Compare a draft against recorded actions.
- **F188 — Separated simulation outcomes:** Report newly denied, newly held, newly constrained, newly allowed, and unevaluable actions independently.
- **F189 — Expanded-exposure visibility:** Treat newly allowed actions as broadened exposure, including in impact comparisons.
- **F190 — Approval-burden forecasts:** Estimate approval requests over the selected evidence period.
- **F191 — Business-impact drill-down:** Inspect representative runs, important workflows, affected owners, and missing context.
- **F192 — Simulation limits:** State that simulation predicts decisions, not agent replanning or guaranteed downstream business results.
- **F193 — Meaningful policy scenario tests:** Test valid lookup, unrelated lookup, approval-threshold hold, grant-limit denial, split-budget prevention, and stale or changed approval failure.
- **F194 — Expected reasons in tests:** Record expected decision and critical reason, not only pass/fail.
- **F195 — Production publication gate:** Require applicable baseline tests to pass before production publication.
- **F196 — Conflict validation:** Identify exact conflicting clauses with an example affected action.
- **F197 — Capability validation:** Check whether integrations can satisfy the proposed policy's constraints and evidence requirements.
- **F198 — Behavioral version diffs:** Explain changed outcomes and thresholds, not just changed text.

### 16. Policy rollout, rollback, and exceptions

*Source: §§8, 11, 26, 28, 30, 38.*

- **F199 — Versioned policy lifecycle:** Draft, validate scope/conflicts/capabilities, test, simulate, shadow, review disruption, pilot, verify, and expand.
- **F200 — Shadow policy evaluation:** Evaluate live covered activity without claiming enforcement.
- **F201 — Named pilot cohorts:** Enforce first for specific agents or cohorts and expand after verification.
- **F202 — Per-target rollout evidence:** Distinguish configured, acknowledged, verified, and exception states by target.
- **F203 — Publication-versus-enforcement distinction:** Do not label all targets enforced merely because a version was published.
- **F204 — Partial rollout recovery:** Retain previous valid controls where possible and show exact targets on older or unconfirmed versions.
- **F205 — Owner-assigned rollout failures:** Assign unresolved targets to accountable platform or connection owners.
- **F206 — Controlled rollback:** Restore a selected prior version subject to current organizational restrictions.
- **F207 — Emergency-control preservation:** Do not remove active emergency containment through ordinary rollback without separate authority.
- **F208 — Narrow temporary exceptions:** Require target, reason, owner, expiry, and permitted approver.
- **F209 — Non-overridable exception limits:** Prevent exceptions from defeating protected non-overridable restrictions.
- **F210 — Fresh exception renewal:** Require new review for renewal rather than automatic extension.

## Operations, investigations, and exposure

### 17. Live Operations

*Source: §§8, 13, 27, 30–31, 38.*

- **F211 — Ranked work queue:** Prioritize active incidents and unconfirmed containment, important waiting decisions, protection failures/authority expansion, and other significant changes.
- **F212 — Attention summary:** Show response needs, waiting approvals and imminent expiry, coverage changes, and qualified no-critical-condition statements.
- **F213 — Freshness-qualified status:** State scope and timestamp; absence of selected critical issues is not an estate-wide safety claim.
- **F214 — Operational actions:** Inspect, assign, suspend runs, revoke grants, and open approvals directly from work items.
- **F215 — Focused live stream:** Surface first sensitive capability use, significant writes, new authority, material expansion, and unexpected denials.
- **F216 — Quiet routine telemetry:** Keep successful routine reads searchable without making them the default stream or headline counter.
- **F217 — Grouped retries:** Combine related retries into expandable items with counts and time range.
- **F218 — Pausable live updates:** Let reviewers pause updates while new arrivals accumulate visibly.
- **F219 — Per-item evidence status:** Show timestamp, freshness, and outcome on each item.
- **F220 — Telemetry-gap visibility:** Show missing observation as a gap rather than an uneventful interval.
- **F221 — Automation exceptions in Operations:** Surface blocked launches, stalled approvals, failed containment, repeated recovery failure, and changed authority; keep routine success in Automations.
- **F222 — Automation-origin drill-down:** Show trigger and workflow version alongside task, agent, grant, and policy for automated actions.
- **F223 — Fast operational comprehension:** Design for identifying attention needs, understanding the triggering action, and making a scoped response; treat five-second/thirty-second/one-minute goals as usability targets, not performance guarantees.

### 18. Run and session inspector

*Source: §§8, 12–14, 19, 21, 38.*

- **F224 — End-to-end run inspection:** Follow a run from task assignment through decisions and final effects.
- **F225 — Run context summary:** Show declared task, launcher, represented principal, grant, status, and coverage.
- **F226 — Chronological run record:** Show actions, decisions, results, and authority changes in order.
- **F227 — Budget and approval history:** Show consumed budget and approvals requested during the run.
- **F228 — Related-work links:** Connect child runs and known downstream workflows.
- **F229 — Unresolved-run evidence:** Show missing evidence, gaps, and unresolved effects.
- **F230 — Run response actions:** Suspend, revoke run authority, inspect decisions, compare, open a case, and export permitted evidence.
- **F231 — Append-only outcome updates:** Keep completed action records stable; append new observations with provenance.
- **F232 — Task-phase timeline:** Group Gather context, Prepare change, Seek approval, Execute, and Verify phases from workflow evidence; mark inferred phases as inferred.
- **F233 — Agent-provided notes:** Allow concise plan summaries or intent notes with explicit provenance and no authority effect.
- **F234 — Typical-run comparison:** Show concrete differences such as new destinations, record counts, or post-task writes, including reference period and sample size.
- **F235 — Novelty uncertainty:** Do not infer maliciousness solely from a difference or new behavior.
- **F236 — Evidence-first inspection:** Avoid requiring full transcripts or access to hidden model reasoning.

### 19. Unified investigations

*Source: §§8, 15, 20, 25, 31, 42–43.*

- **F237 — Action-to-case creation:** Open a suspicious action into a persistent investigation workspace with linked task and prior context.
- **F238 — Shared investigation scope:** Switch Sequence, Authority, Effects, Reach, Related activity, and Response lenses without losing selected run or time range.
- **F239 — Decision and execution verification:** Establish whether an action was allowed, held, denied, observed, dispatched, or supported by confirmed effects.
- **F240 — Origin tracing:** Trace launcher, represented principal, grantor, and child delegation.
- **F241 — Preceding-context review:** Inspect recent grant changes, new tools, external-content provenance, and other relevant prior activity.
- **F242 — Related-activity queries:** Find shared destinations, resources, credentials, external documents, action sequences, grants, and tool changes.
- **F243 — Narrow containment guidance:** Prefer the smallest relevant response scope unless evidence supports wider action.
- **F244 — Actual-versus-potential impact:** Keep observed effects and possible exposure separate.
- **F245 — Confirmed facts field:** Link each asserted fact to supporting evidence.
- **F246 — Hypotheses field:** Record analyst or product inference with confidence and alternatives.
- **F247 — Open questions field:** Track evidence needed to resolve uncertainty.
- **F248 — Instruction-injection evidence:** Link suspicious external content and resulting actions without treating suspicious text alone as proven causation.
- **F249 — Case collaboration:** Assign owners, annotate, preserve evidence, query related actions, and export or hand off cases to existing security workflows.
- **F250 — Evidence-preserving case updates:** Add evidence without replacing notes or silently revising conclusions.
- **F251 — Case closure requirements:** Require containment state, confirmed effects or explicit unresolved impact, follow-up owner, disposition, and supporting evidence.
- **F252 — Separate operational and forensic status:** Allow operational containment while historical-impact questions remain open.

### 20. Risk and blast-radius analysis

*Source: §§12, 17–19, 31, 38–41.*

- **F253 — Observed-effects view:** Show what the actor actually accessed or changed with evidence.
- **F254 — Effective-reach view:** Show what current grants and policies permit through protected paths.
- **F255 — Credential-and-bypass view:** Show broader technical reach from credentials and unprotected routes separately.
- **F256 — Reachable-resource analysis:** Display resource groups, permitted operations, sensitivity, task limits, downstream delegation, expiry, and coverage confidence.
- **F257 — Explainable prioritization:** Rank by consequence, scope, present usability, enforceability, ownership, and remediation readiness rather than an unexplained universal score.
- **F258 — Dynamic reach recomputation:** Update after grant, policy, resource-relationship, or coverage changes; label stale dependencies.
- **F259 — Authority-reduction actions:** Revoke grants, remove dangerous capabilities, isolate connections, and preview restrictions.
- **F260 — Reach-evidence drill-down:** Inspect specific targets, authority paths, credential relationships, and affected runs.
- **F261 — Active and conditional exposure:** Distinguish currently usable, conditional, expired, and uncertain rights.
- **F262 — Automation latent exposure:** Include both current execution reach and maximum future grant-issuance ceiling, even for a quiet schedule.

### 21. Dependency previews and posture remediation

*Source: §§8, 17–18, 25–26, 38–41.*

- **F263 — Connection-disable preview:** Show active dependent runs, waiting actions becoming invalid, expected workflows, alternative resource paths, and unknown dependencies.
- **F264 — Emergency preview bypass record:** Permit authorized emergency containment before completing impact preview, while recording the skipped assessment.
- **F265 — Posture remediation queue:** Surface excessive grants, uncovered paths, unowned agents, unsafe delegation, stale credentials, unused authority, and unverified sensitive tools.
- **F266 — Root-cause finding groups:** Combine findings by shared cause while preserving evidence and status history.
- **F267 — Actionable finding detail:** Show exposure, evidence period, unseen paths, suggested change, and next validation step.
- **F268 — Posture actions:** Assign owners, simulate restrictions, expire grants, verify connections, and accept time-limited exceptions.
- **F269 — Finding lifecycle:** Track Open, Assigned, Testing, Remediated, Accepted temporarily, and Evidence incomplete.
- **F270 — Evidence-based remediation closure:** Require proof that the change reaches affected paths; dismissing an alert does not close exposure.
- **F271 — Restriction dependency comparison:** Show before/after reach and expected workflow disruption for proposed authority reduction.

## Graphs, search, and onboarding

### 22. Evidence-backed graphs and visual analysis

*Source: §§12, 17, 19, 38–43.*

- **F272 — Activity relationship map:** Show a selected agent, represented principals, and contacted resources in a selected period, distinguishing reads, writes, disclosures, and delegation.
- **F273 — Observed-versus-possible edges:** Keep observed attempts and outcomes separate from possible access; a denied edge does not imply the destination was reached.
- **F274 — Authority graph:** Trace verified issuers and grants with scope, expiry, applicable constraints, and revoked, missing, or unsupported steps.
- **F275 — Exposure graph:** Show effective reach, technical credential capability, child delegation, and uncovered paths with uncertainty.
- **F276 — Change-comparison graph:** Compare added, removed, constrained, and unresolved relationships before and after a restriction; preserve positions and highlight named changes.
- **F277 — Equivalent-route bypass graph:** Map MCP, direct API, Git/SSH, browser, and other routes capable of the same effect; distinguish tested control from possible or unverified bypass.
- **F278 — Current-coverage graph:** Show per-route control or closure evidence, unknown routes, aggregate boundary state, scope, time, expiry, and reasons for change.
- **F279 — Transaction-causal graph:** Link task authority, exact action, approval, custody, direct effects, reviewed trigger rules, downstream operations, and observed outcomes.
- **F280 — Causal-evidence labeling:** Separate temporal order, possible consequences, hypotheses, and confirmed causal links; require linked trigger evidence and reviewed settings for causal claims.
- **F281 — Direct/downstream effect graph:** Distinguish a confirmed merge, triggered deployment, accepted deployment, and per-service convergence or pending state.
- **F282 — Child-delegation graph:** Show narrowed child authority and independent organization requirements without implying automatic inheritance of parent rights.
- **F283 — Workflow graph:** Show automation conditions, branches, human exceptions, response steps, verification, and completion evidence; each step opens its own authority and failure detail.
- **F284 — Session timeline:** Show action order, holds, approvals, authority changes, dispatch, results, evidence gaps, and parallel child lanes.
- **F285 — Sensitive-read markers:** Mark data reads preceding disclosure attempts without claiming causation beyond the evidence.
- **F286 — Exposure matrix:** Compare agents by resource group and read/export/update/delete/transfer/delegate operations, including effective scope, approval, and coverage.
- **F287 — Policy-impact comparison:** Compare current and proposed outcomes by workflow and consequence, including newly blocked normal work, expanded permissions, missing context, and expected approval burden.
- **F288 — Containment progress visualization:** Show affected agents, grants, paths, and in-flight actions as Requested, Confirmed, Unsupported, Failed, or Unknown; avoid global success while any material path is unresolved.
- **F289 — Distinct graph modes:** Keep Activity, Authority, Exposure, and Change comparison meanings explicit; mode switching preserves selected objects and changes the legend.
- **F290 — Shared edge vocabulary:** Show stable endpoints, named relationships, decision, coverage, execution, effect, evidence basis, revisions, observation time, validation, expiry, and invalidating changes.
- **F291 — Explicit edge states:** Include Enforced, Allowed, Approval required, Denied, Observed, Possible bypass, Unknown, Stale, and exact partial/pending/conflicting/unverifiable effects.
- **F292 — Historical relationship inspection:** Retain expired, revoked, quarantined, and blocked relationships historically while excluding them from current usable authority.
- **F293 — Focused graph scope:** Start from one task, agent, incident, or resource group; aggregate fleets by team, capability, or common cause and expand on demand.
- **F294 — Protection-gap preservation:** Keep critical gaps visible when collapsing nodes or repeated activity.
- **F295 — Selectable evidence edges:** Open supporting action cards, grant evidence, access sources, closure controls, revocation options, and missing facts from relationships.
- **F296 — Graph filtering:** Filter by time, run, agent, operation, decision, outcome, and represented principal; show repeated use and aggregate scope without duplicate-edge overload.
- **F297 — Graph freshness and provenance:** Show evidence period and freshness; label inferred, stale, declared, tested, authoritative, and unverified relationships.
- **F298 — Accessible graph tables:** Provide an equivalent permission-scoped table for every graph and text labels for edge meaning.
- **F299 — Evidence-based containment comparison:** Retain earlier reads and historical-impact questions after revocation; edge removal alone does not establish closure.
- **F300 — Permission-safe graph queries:** Apply underlying tenant and data permissions to expansion, counts, summaries, queries, and exports so hidden records cannot be inferred.
- **F301 — Posture and operating charts:** Plot coverage/staleness, consequential effects/outcomes, bypass-route age/owner, exposure by resource group, verification/reconciliation backlog, and automation completion/intervention/unresolved effects.
- **F302 — Chart-to-evidence drill-down:** Open each series to its scope and supporting records; unknown discovery coverage cannot become an estate-wide safety percentage.
- **F303 — Appropriate visual format:** Prefer a sortable table for ranking and a timeline for sequence when they answer the question more clearly than a graph.

### 23. Universal search and saved queries

*Source: §§8, 19–20, 27, 42.*

- **F304 — Natural-language and structured search:** Search the same permission-scoped evidence with plain-language questions or explicit filters.
- **F305 — Inspectable query interpretation:** Show generated query, environment, date range, timezone, and whether results cover attempts, confirmed access, or other event meanings.
- **F306 — Production-access search:** List agents and linked actions, separating attempts from confirmed successful access.
- **F307 — Decision-explanation search:** Answer why an action was allowed using conditions retained at decision time.
- **F308 — Current-authority search:** Find agents able to write a resource, separating grant-constrained authority from technical reach.
- **F309 — Tool-capability search:** Find tools capable of effects such as payments, distinguishing verified capabilities from unclassified tools.
- **F310 — Unused-permission search:** Find grants without observed use, retaining evidence windows and coverage gaps.
- **F311 — Represented-principal search:** Find actions performed for a person without confusing that person with the launcher.
- **F312 — Dependency search:** Preview what disabling a connection affects, including unknown dependencies.
- **F313 — Exposure ranking search:** Rank widest exposure with explicitly selected criteria.
- **F314 — Denial search:** Find denied actions against a provider or resource while distinguishing enforced denials from shadow predictions.
- **F315 — Authority-change search:** Find recent grants and policy expansions, separating material scope changes from metadata edits.
- **F316 — Incident correlation search:** Find shared external documents, destinations, credentials, sequences, grant changes, and tool changes.
- **F317 — Result context:** Show query scope, evidence range, freshness, omissions, and supporting links.
- **F318 — Search actions:** Refine, save, share within permissions, open a case, and export allowed results.
- **F319 — Live-versus-historical search:** Mark changing live results and keep historical ranges stable.
- **F320 — Permission-safe search outputs:** Apply resource/data permissions to results, suggestions, counts, summaries, and exports.
- **F321 — Evidence-grounded answers:** Do not invent records or produce an answer lacking links to supporting evidence.

### 24. Developer onboarding and debugging

*Source: §§9–11, 21, 28, 34, 36.*

- **F322 — One-workflow onboarding:** Begin with one agent or supported runtime, an owner, and a development environment.
- **F323 — Identity and tool inspection:** Verify execution identity and show connected tools and uncovered paths.
- **F324 — Task setup:** Select a template and name resources, operations, limits, and duration.
- **F325 — Safe observation test:** Run safe work and inspect its action and authority explanation.
- **F326 — Positive and negative tests:** Try both a permitted action and an intentionally out-of-scope action.
- **F327 — Verified protected-path setup:** Enforce a named path and verify that the prohibited test is stopped.
- **F328 — Credential-overreach insight:** Show when the connection can delete or export although the task only needs reads and updates.
- **F329 — Scoped coverage card:** Confirm the tested path and name remaining uncovered tools.
- **F330 — Local debugging detail:** Show decision ID, exact failed boundary, redacted request, effective grant and policy, and whether identity, scope, approval, context, or connection capability caused the block.
- **F331 — Developer recovery links:** Offer a permitted alternative, exception request, or authorized grant correction.
- **F332 — Matching-case handoff:** Open the same request as a case without requiring manual reconstruction.
- **F333 — Production promotion checks:** Validate ownership, identity, required tests, approval routing, coverage, and failure behavior before promotion.
- **F334 — Scoped readiness statement:** State readiness for specific production operations rather than claiming universal safety.
- **F335 — Onboarding usability target:** Aim for one verified insight and one verified protected path in roughly 30 minutes for a supported integration with available credentials; do not present it as a universal guarantee.

### 25. Security-team onboarding and expansion

*Source: §§22–23, 25, 28, 36.*

- **F336 — Narrow business-workflow start:** Begin with one owner, consequential tool, and task without requiring a full enterprise inventory.
- **F337 — Ownership and reach baseline:** Confirm identity and ownership, then compare credential reach with task authority.
- **F338 — Trusted-input setup:** Connect relevant identity and classification sources and select organizational guardrails.
- **F339 — Representative-work review:** Observe real representative actions or an unmistakably labeled demonstration.
- **F340 — Restriction impact review:** Simulate a restriction and inspect effects on the business workflow.
- **F341 — Approval and denial validation:** Verify an enforced deny and a working valid approval workflow.
- **F342 — Suspension exercise:** Test suspension and verify actual response effects.
- **F343 — Dependency-led recommendations:** Recommend identity, classification, approval, and incident connections based on discovered needs.
- **F344 — Recommendation capability disclosure:** Explain what each connection enables and what remains unsupported without it.
- **F345 — Evidence-based onboarding completion:** Establish ownership, usable authority, decision explanation, and stopping capability using the customer's own workflow evidence.

## Connections, tool meaning, and coverage

### 26. Capability-aware integration catalog and connection lifecycle

*Source: §§8, 21–24, 28, 36, 39–41.*

- **F346 — Job-based integration discovery:** Search integrations by enforcement, people verification, data classification, approvals, evidence export, or response controls.
- **F347 — Separate capability declarations:** Distinguish discovery, observation, enforcement, and response support.
- **F348 — Supported-operation manifest:** Declare actions, parameter constraints, result inspection, identity attribution, and resource attribution.
- **F349 — Permission explanations:** Show requested permissions and why each is needed before connection.
- **F350 — Integration limits:** Disclose unsupported operations, exclusions, failure behavior, verification tests, and last successful test.
- **F351 — Environment-specific connection setup:** Choose intended capability and environment before configuring access.
- **F352 — Tool/resource discovery:** Discover available tools and resources after connection.
- **F353 — Sensitive capability review:** Require review and explicit approval of sensitive capabilities before use.
- **F354 — Harmless capability tests:** Test supported behavior without consequential customer changes.
- **F355 — Enforcement tests:** Where supported, use a deliberately prohibited action to verify stopping behavior.
- **F356 — Declared coverage publication:** Publish tested connection coverage separately from mere connection setup.
- **F357 — Observation-only labeling:** Permit discovery through observation-only access without giving it an enforcement badge.
- **F358 — Connection health detail:** Show health, permissions, capabilities, catalog, tests, delivery failures, and dependent agents.
- **F359 — Connection management actions:** Connect, test, approve capabilities, quarantine, rotate access where supported, and disconnect.
- **F360 — Explicit coverage changes:** Turn capability drift, failed tests, unavailable observations, and stale signals into visible coverage changes.

### 27. Customer-defined integrations and external signals

*Source: §§23–24, 36, 40–41.*

- **F361 — Guided action definitions:** Ask customers to define action names, stable resource identity, and material scope/money/recipient/destination parameters.
- **F362 — Side-effect and reversibility definition:** Record direct effects, side effects, and recovery limits.
- **F363 — Attribution and results definition:** Specify identity evidence, result states, constraints, cancellation, and supported response.
- **F364 — Failure and test scenarios:** Define failure cases and safe validation scenarios.
- **F365 — Customer-controlled validation:** Test declared behavior and limit claims to the tested capability and scope.
- **F366 — External classification support:** Consume trusted data classifications with provenance and freshness.
- **F367 — External policy and risk inputs:** Use mapped policy checks and risk signals with stated provenance and failure behavior.
- **F368 — Required-check failure handling:** Return Cannot authorize when an external source required for a decision is missing; follow published wait/deadline behavior without dropping the requirement.
- **F369 — Extension privilege ceiling:** Prevent extensions from granting beyond core authority or organizational boundaries.
- **F370 — Existing-provider reuse:** Reuse existing identity and policy decisions only where explicit mappings are tested.
- **F371 — Execution-contract preservation:** External allow or approval results do not waive custody, current coverage, exact execution, or verification requirements.

### 28. Reviewed tool packages and action definitions

*Source: §§7, 23, 26, 35–36, 40.*

- **F372 — Internal reusable packages:** Publish owned, versioned integration packages with a capability manifest, tests, and change history.
- **F373 — Package adoption review:** Preview requested permissions; require explicit review for capability-widening updates.
- **F374 — Tool metadata detail:** Show name, version, input meaning, affected resource types, read/write classification, and known side effects.
- **F375 — Effect-based definitions:** Map equivalent operations across MCP, API, and wrappers to the same reviewed action meaning.
- **F376 — Definition execution channels:** Identify supported provider operations and channels.
- **F377 — Stable account and target boundaries:** Bind meaning to stable resource identity, tenant/account, and relevant target settings.
- **F378 — Material parameter interpretation:** Define units, amounts, currency, recipients, destinations, and other decision-relevant fields.
- **F379 — Effect and reversibility documentation:** Describe direct effects, known side effects, and irreversibility limits.
- **F380 — Constraint documentation:** Specify safe supported limits and transformations.
- **F381 — Prerequisite documentation:** Identify required target conditions, classifications, and history.
- **F382 — Retry and verifier documentation:** Specify safe retry, ambiguous-outcome behavior, required verification, and what it establishes.
- **F383 — Definition assurance metadata:** Record version, evidence basis, reviewers, compatible versions/settings, last behavior verification, validity, expiry, and exclusions.
- **F384 — No description-only trust:** Do not treat a tool's text description or stable schema as proof of its security behavior.
- **F385 — No automatic new capability rights:** Added sensitive operations do not inherit authority from previous grants.
- **F386 — Ambiguous-input rejection:** Do not silently choose safe defaults for unresolved targets, unknown material fields, unsupported units, or malformed amounts.
- **F387 — Opaque capability labels:** Label insufficiently understood tools explicitly and limit claimed controls.

### 29. Tool meaning workbench, assurance, and drift

*Source: §§9, 23, 26, 38, 40–41.*

- **F388 — Inspectable meaning workbench:** Show definitions, direct effects, supported consequences, settings, evidence, tests, revisions, expiry, and discrepancies.
- **F389 — Meaning governance actions:** Draft mappings, review evidence, test, simulate changes, approve exact versions, quarantine, and restore affected definitions.
- **F390 — Definition drill-down:** Open source tools, fixtures, consequence rules, policies, transactions, and drift findings.
- **F391 — Three assurance sources:** Distinguish declared contracts, documented provider behavior, and controlled observations in an approved test context.
- **F392 — Evidence disagreement retention:** Keep inconsistencies visible rather than selecting the convenient interpretation.
- **F393 — Periodic behavior validation:** Use safe checks on isolated resources with approved credentials and bounded budgets; consequential customer testing needs separate authority.
- **F394 — Definition lifecycle:** Track Unclassified, Draft, Reviewed, Active, Expired or stale, Quarantined, and Retired.
- **F395 — Separate review and activation:** Reviewed definitions still need explicit target-scope activation.
- **F396 — Expired-meaning stop:** Stop affected authorization when required behavioral evidence expires or becomes stale.
- **F397 — Quarantined-effect stop:** Suspend affected effects while material mismatch or compromise is unresolved.
- **F398 — Historical retired definitions:** Retain old versions for evidence while preventing new use.
- **F399 — Behavior drift detection:** Recognize behavior and target-configuration changes even when tool schema and name stay unchanged.
- **F400 — Old-versus-new drift finding:** Show changed evidence and impacted agents, policies, transactions, and owners.
- **F401 — Dependency invalidation:** Quarantine affected meanings/rules, invalidate material coverage and waiting approvals, and stop dependent automation steps.
- **F402 — Reviewed restoration:** Require fresh reviewed behavior evidence before restoring affected use.
- **F403 — Validated unaffected separation:** Permit unaffected definitions or steps only when their independence is explicit and verified.
- **F404 — No automatic model mapping activation:** Model-proposed meanings remain drafts or hypotheses until governed validation and activation.

### 30. Downstream-consequence authorization

*Source: §§7, 10, 19, 36, 38, 40, 42–43.*

- **F405 — Reviewed conditional consequence rules:** Define possible triggered effects under named and verified conditions.
- **F406 — Direct and downstream scope separation:** Treat a repository merge and its supported production deployment as different effects requiring appropriate authority.
- **F407 — Target-setting evidence:** Retain the configuration linking a direct effect to a downstream workflow.
- **F408 — Consequence-aware policy gates:** Apply production authority, release approval, time windows, and other controls when a reviewed consequence applies.
- **F409 — Consequence explanation:** Show named rule, target relationship, supporting settings, validity, and unknown intermediate steps.
- **F410 — Prediction-versus-permission labels:** Distinguish may-cause, authorized consequence, accepted downstream operation, confirmed target state, and consequence unknown.
- **F411 — Bounded consequence chains:** Use named rules with declared depth/scope; preserve resource identity and conditions across links.
- **F412 — Unknown-link handling:** Stop definitive derivation at missing links; request evidence, isolate the known direct action, or refuse work when policy requires consequence assurance.
- **F413 — No arbitrary model causality:** Do not invent enterprise consequence chains from free-form reasoning.
- **F414 — Per-consequence verification:** Verify supported downstream outcomes separately from direct action acceptance and direct-effect confirmation.
- **F415 — Effect-dependent workflow progression:** Wait for the required direct or downstream state before smoke tests, follow-on operations, or completion reports.

### 31. Credential custody and access detail

*Source: §§12, 17, 23, 25–26, 35–36, 39, 41, 43.*

- **F416 — Action-bound target authority:** Within an enforced boundary, exercise only access required for the currently authorized action; the agent must not retain reusable access that defeats the decision.
- **F417 — Target-enforced mode:** Use target-side validation where supported and disclose exact constraints and evidence.
- **F418 — Narrow temporary-access mode:** Limit access by target, scope, audience, duration, and supported conditions; disclose unenforceable restrictions.
- **F419 — PantherClaw-held mode:** Perform approved work using credentials the agent cannot retrieve; show actual target permissions and custody assurance.
- **F420 — Externally constrained runtime mode:** Identify independently validated controls confining the actor's target reach.
- **F421 — Agent-held reusable-access mode:** Disclose broader direct access and partial/unknown coverage unless independent controls close its equivalent routes.
- **F422 — Combined access modes:** Support combined modes without treating short expiry alone as single-action protection.
- **F423 — Access source inspection:** Show custodian, target account, scope, audience, expiry, issuer, affected agents, verification basis, and residual routes without exposing secrets.
- **F424 — Access management actions:** Restrict scope, test custody, remove direct access, revoke/rotate where supported, and preview dependent work.
- **F425 — Access graph drill-down:** Link credential paths, integrations, grant lineage, transactions, and revocation evidence.
- **F426 — Change-based access invalidation:** Reassess after identity, privilege, credential, retrieval permission, or target changes.
- **F427 — Revocation completeness:** Report both delegated permission removal and outstanding usable target access.
- **F428 — Shared credential dependencies:** Show all affected workloads rather than treating shared credentials as agent-specific.
- **F429 — Actual rotation verification:** Distinguish confirmed target rotation from editing a local setting.
- **F430 — Credential-exposure investigation:** Investigate all known dependent identities and routes after exposure.
- **F431 — Executor trust assurance:** State whether protection assumes a trusted executor or independently contains a compromised actor; a check that the actor can ignore does not justify stronger assurance.
- **F432 — No ordinary secret reveal:** Keep raw credentials and reveal-token controls outside normal investigation.

### 32. Continuous scoped coverage records

*Source: §§1, 5, 9–10, 19, 23, 36, 39, 41.*

- **F433 — Effect-based protection question:** Assess whether the workload can produce the same consequential effect through another usable route without authorization.
- **F434 — Scoped coverage record:** Name workload instance/cohort, target, account, resource class, effect, channels, equivalent routes, controls, validation, exclusions, time, expiry, invalidating changes, owner, and next verification.
- **F435 — Unknown coverage state (`UNKNOWN`):** Show missing route/usability/control evidence and make no enforced claim.
- **F436 — Observe-only coverage state (`OBSERVE_ONLY`):** Show activity visibility without claiming prevention.
- **F437 — Partial coverage state (`PARTIAL`):** Identify controlled routes and the material equivalent routes that are possible, unverified, or excluded.
- **F438 — Enforced coverage state (`ENFORCED`):** Claim enforcement only for the declared workload/target/effect/time boundary with material supported routes mediated or independently proven blocked.
- **F439 — Separate assurance dimensions:** Keep coverage distinct from policy correctness, reviewed tool meaning, and verified outcomes.
- **F440 — Published freshness contract:** Disclose detection/update timing and when evidence stops supporting a claim.
- **F441 — Expired-evidence downgrade:** Do not preserve yesterday's enforced status after expiry or failed refresh.
- **F442 — Last-valid evidence:** Retain the last valid coverage record and explain what invalidated it.

### 33. Equivalent routes and coverage maintenance

*Source: §§19, 23, 31, 38–41, 43.*

- **F443 — MCP and tool route inventory:** Consider tool routes capable of the same effect.
- **F444 — API and SDK route inventory:** Consider direct providers and SDK calls, including access outside the visible connection.
- **F445 — Host route inventory:** Consider shell, CLI, filesystem mutations, executable wrappers, Git, SSH, mounted keys, and retrievable credentials.
- **F446 — Browser route inventory:** Consider authenticated browser sessions and user contexts.
- **F447 — Delegated route inventory:** Consider child agents and delegated services.
- **F448 — Intermediate route inventory:** Consider CI/CD, webhooks, schedules, queues, and other effect-producing intermediaries.
- **F449 — Target-side authority inventory:** Inspect relevant target identities and permissions beyond the agent's visible tools.
- **F450 — Discovery-source limits:** Show where route inventory has no reliable source; missing inventory is not proof of route absence.
- **F451 — Coverage workbench:** Show usability, credentials, channels, equivalent effects, controls, tests, freshness, expiry, and exclusions.
- **F452 — Coverage remediation actions:** Investigate routes, assign owners, remove access, connect controls, run permitted probes, verify closure, or restrict workflows.
- **F453 — Coverage invalidation events:** Reassess after credential/retrieval changes, identity/build/host changes, child authority, egress/target access changes, new channels/operations, meaning/consequence changes, failed tests, expiry, or lost required sources.
- **F454 — Automated evidence maintenance:** Preauthorized workflows gather evidence, propose routes, probe safely, assign remediation, and retest controls.
- **F455 — Evidence-only promotion:** Promote coverage only from retained supported evidence; model confidence and proposed routes are not proof of closure.
- **F456 — Stale-coverage workflow handling:** Follow declared sensitive-work boundary policy rather than dropping the coverage requirement to continue.
- **F457 — Route-specific closure evidence:** Record tested identity/effect, blocking control, scope, and reopening conditions.
- **F458 — Independent route closure:** Revoking one token does not establish closure of a browser session or SSH key.
- **F459 — Before/after closure comparison:** Compare route graphs and open each closing control's evidence.
- **F460 — No setting-based enforcement badge:** Connection configuration alone does not establish enforced coverage or a meaningful protection percentage.

## Transactions, verification, and evidence

### 34. Linked transaction receipts and evidence explorer

*Source: §§1, 7, 10, 24, 26, 38, 42–43.*

- **F461 — Decision receipt:** Retain actor, principal, task grant, exact action, policy/meaning versions, facts, history, coverage, requirements, and decision reason.
- **F462 — Execution receipt:** Retain effective action, execution actor, access mode, attempts, final consent, dispatch time, target response, cancellation, and uncertainty.
- **F463 — Effect receipt:** Retain verifier, observed state, expected/observed effect, timestamps, basis, exact result, and limitations.
- **F464 — Linked and versioned receipts:** Connect the three records under the logical transaction with retained revisions.
- **F465 — Non-rewriting observations:** Append later evidence without rewriting original decisions or erasing target responses.
- **F466 — Evidence explorer:** Inspect receipts, observations, revisions, consent, integrity status, data handling, retained facts, and gaps independently of a generated summary.
- **F467 — Evidence comparison and assembly:** Compare records, assemble evidence packs, export allowed scope, and request reconciliation.
- **F468 — Evidence drill-down:** Open grants, approvals, policies, definitions, coverage snapshots, external observations, and privileged changes.
- **F469 — Unavailable-payload labeling:** Show expired or deleted payloads as unavailable, separately from an action never existing.
- **F470 — No invented reconstruction:** Do not reconstruct missing inputs, expose raw secrets, dump mandatory transcripts, or replace contradictory records with one success label.

### 35. Execution lifecycle states

*Source: §§10, 25, 28, 38–39, 42–43.*

- **F471 — Requested:** Record that the logical action was received and attributed.
- **F472 — Blocked:** Establish that no dispatch occurred because of denial or inability to authorize.
- **F473 — Waiting:** Show the named approval, authentication, prerequisite, or permitted recovery wait.
- **F474 — Authorized:** Show final authorization without implying dispatch.
- **F475 — Dispatched:** Record the sent target request without assuming completion.
- **F476 — Accepted:** Record target acknowledgment without assuming the required effect occurred.
- **F477 — Failed:** Record supported failure evidence and preserve separately visible partial effects.
- **F478 — Cancelled:** Claim cancellation only when supported evidence establishes its stated scope.
- **F479 — Decision/execution/effect separation:** Do not equate permission with dispatch, dispatch with success, or a success response with verified effect.

### 36. Effect-result states and safe progression

*Source: §§10, 17, 19, 25, 28, 38, 40, 42–43.*

- **F480 — Effect confirmed:** Establish the named intended effect with required evidence; dependent work still needs its own valid conditions.
- **F481 — No effect confirmed:** Establish non-occurrence only in the checked scope and reassess any retry under current authority.
- **F482 — Partial effect:** Identify which intended changes or targets completed and authorize recovery separately.
- **F483 — Propagation pending:** Retain known acceptance with incomplete convergence; wait within verifier deadlines and block dependencies requiring completion.
- **F484 — Conflicting evidence:** Preserve disagreeing authoritative observations and route reconciliation.
- **F485 — Unverifiable:** State that the integration lacks a supported method for the required effect and avoid a verification claim.
- **F486 — Outcome unknown:** Keep occurrence or result unresolved; reconcile before another irreversible attempt.
- **F487 — Compensated:** Link a separately authorized compensating transaction while preserving original action and residual consequences.
- **F488 — Qualified verified summary:** Use verified only with the exact result, scope, and basis, not as a synonym for business success.
- **F489 — Domain-specific effect meaning:** Distinguish objects such as accepted refunds from actual settlement or customer receipt of money.
- **F490 — Named multi-target outcomes:** Show which services or resources reached expected state and which remain partial, pending, or unknown.

### 37. Verification levels, sources, deadlines, and reconciliation

*Source: §§10, 23, 25, 38–43.*

- **F491 — Transport/acceptance verification:** Establish delivery or acknowledgment without claiming business completion.
- **F492 — Follow-up state observation:** Use a supported independent read to establish named target state without claiming every downstream effect.
- **F493 — Domain-effect confirmation:** Use domain evidence to verify the required effect within its checked scope.
- **F494 — Downstream confirmation:** Verify a named supported consequence without extending the claim to arbitrary causal chains.
- **F495 — Required-versus-achieved level:** Show the verification level policy requires and the level available evidence reaches.
- **F496 — Independent verification where feasible:** Use separately authorized sources beyond the executor's assertion; show verifier identity, authority, observed state, and limitations.
- **F497 — Unsupported-verifier gate:** Stop authorization when required verification capability cannot be performed within the declared scope.
- **F498 — Contradictory observation retention:** Preserve acknowledgment and conflicting follow-up observations together until resolved.
- **F499 — Verifier deadlines:** Record timeout deadline and supported pending, unknown, or unverifiable result.
- **F500 — Dependent-step wait:** Require the qualifying effect state before dependent work proceeds.
- **F501 — Owned reconciliation queue:** Assign accountable reconciliation owners and track unresolved work with outstanding reservations.
- **F502 — Authorized recovery transactions:** Treat compensation and recovery as new authorized actions linked to the original.
- **F503 — Irreversibility limits:** Do not imply that compensation exactly reverses a disclosure or transfer.

### 38. Decision replay and receipt integrity

*Source: §§11, 26, 40, 42.*

- **F504 — Original-decision replay:** Reproduce a decision using the retained request, authority, facts, policy, meaning, and history.
- **F505 — Proposed-policy replay:** Evaluate how the recorded request would be decided under a proposed rule.
- **F506 — Difference explanation:** Identify changed inputs that explain different decisions.
- **F507 — Replay limitations:** Show retained versions, compatibility limits, and missing dependencies; report Incomplete replay when required context is unavailable.
- **F508 — Non-executing replay:** Never send the original target action during explanation replay; execution retry is separately authorized and reconciled.
- **F509 — Receipt integrity inspection:** Show available integrity checks, authorized corrections, export history, and publication identities.
- **F510 — Bounded signature assurance:** Explain that a verified signature supports stated issuer/content checks, not issuer honesty or occurrence of external effects.
- **F511 — Honest integrity language:** Use integrity checked and evidence-backed without claiming universal tamper-proof history or non-repudiation.

### 39. Privacy, retention, and evidence permissions

*Source: §§4, 10, 16, 19–20, 24, 26–28, 33, 42.*

- **F512 — Separate retention categories:** Configure raw payloads, normalized action facts, receipts, approvals, policy/tool versions, security audit, and operational traces separately.
- **F513 — Purpose-bound payload capture:** Do not collect raw requests/responses merely because they exist; require an explicit profile and purpose for restricted capture.
- **F514 — No secret retention in ordinary evidence:** Exclude credentials, tokens, private keys, and raw secrets from normal receipts and exports.
- **F515 — Source-permission propagation:** Apply originating permissions to search, summaries, graphs, counts, packs, and export.
- **F516 — Restricted-evidence access auditing:** Audit separately authorized access to sensitive evidence; platform administration is not automatic payload access.
- **F517 — Explicit export destinations:** Define authorized destinations and data scope; filter sensitive parameters and redact as required.
- **F518 — Retention holds and deletion:** Respect holds and authorized deletion workflows, preserving permitted history and deletion records.
- **F519 — Deletion-impact explanation:** Show how deletion reduces replay or verification capability.
- **F520 — No deleted-payload recreation:** Do not rebuild deleted content or dispatch again from a repeated request after deletion.
- **F521 — Unavailable-evidence distinction:** Preserve the action's existence even when payload access or retention has ended.
- **F522 — Permission-safe channel content:** Keep email/chat notifications and external approvals from exporting restricted customer data.
- **F523 — Actual residency commitments:** Describe residency and retention commitments only according to supported behavior.
- **F524 — Task-summary option:** Support concise task summaries and narrowly justified content evidence under explicit access and retention rules without mandatory conversation or hidden-reasoning capture.

### 40. Evidence collections, packs, and export

*Source: §§8, 15, 20, 24, 26, 31, 38, 42–43.*

- **F525 — Audit evidence collections:** Preserve decision/execution history, grant issuance/delegation/expiry/revocation, policy versions/tests/reviews/rollout, exact approval identity/scope, response/restoration, and coverage gaps/tests.
- **F526 — Transaction and incident packs:** Export selected identities, resources, scope, time range, exact transactions, and linked receipts.
- **F527 — Revision-complete packs:** Include grant, policy, meaning, approval, and coverage versions relevant to the selected work.
- **F528 — Uncertainty-complete packs:** Include confirmed, partial, pending, conflicting, unknown, and other material effect states rather than only successful outcomes.
- **F529 — Response-complete packs:** Include containment and recovery evidence.
- **F530 — Pack privacy metadata:** State retention limits, redactions, exporting principal, destination, time, and supported integrity checks.
- **F531 — Evidence-pinned exported graphs:** Pin the same identities and evidence as receipts; do not export unsupported relationships as facts when the supporting evidence is unavailable.
- **F532 — Audit-gap disclosure:** Disclose missing data and coverage gaps; exports aid review without certifying compliance.
- **F533 — Automation evidence exports:** Include trigger, workflow version, step transaction, consent, and effect receipts; completion summaries resolve to actual completion evidence.

### 41. SIEM/SOAR delivery and external response

*Source: §§23–25, 27–28, 31, 38.*

- **F534 — Structured security export:** Send stable event, action, run, agent, grant, and incident IDs with timestamps, environment, actors, decision reason, policy version, execution, effects, coverage, and uncertainty.
- **F535 — Permission-checked source links:** Include deep links that enforce source evidence permissions.
- **F536 — Destination-scoped payload filtering:** Filter sensitive parameters to the destination's approved data scope.
- **F537 — Delivery health:** Show last delivery, delayed and failed records, and retries.
- **F538 — Deduplicable forwarding:** Retain stable IDs on retries and distinguish out-of-order arrival from actual action order.
- **F539 — Enabled-versus-verified delivery:** Separate export configuration from delivery confirmation.
- **F540 — Operational forwarding failures:** Surface failures threatening required monitoring or audit coverage in Operations and follow declared recovery behavior.
- **F541 — Permissioned external response:** Allow SOAR requests for supported scoped controls only with explicit response permission.
- **F542 — External request audit:** Record target scope and reason.
- **F543 — External response results:** Return confirmed, failed, unsupported, or unknown states.
- **F544 — Idempotent response requests:** Repeating a supported response request must not multiply its effect.
- **F545 — External governance preservation:** Keep separation of duties and restoration rules in force for outside workflows.
- **F546 — Incident field ownership:** Declare which system owns each synchronized field; changing ticket status alone cannot restore suspended authority.

## Response, governance, and operational behavior

### 42. Scoped incident response and emergency controls

*Source: §§8, 15, 17, 19, 24–25, 31, 38–39, 43.*

- **F547 — Deny one action:** Stop the current covered attempt while making remaining authority visible.
- **F548 — Hold consequential writes:** Preserve supported reads while preventing covered changes.
- **F549 — Suspend a run:** Refuse new covered actions in that run without claiming its process has stopped.
- **F550 — Revoke a grant:** Remove delegated and dependent authority while tracking in-flight operations separately.
- **F551 — Suspend an agent:** Prevent new covered work across its runs; disclose remaining shared-credential paths.
- **F552 — Quarantine a connection:** Stop covered use through the connection while retaining visibility of alternative connections.
- **F553 — Protect a resource:** Apply temporary restrictions to named targets where resource-level enforcement is supported.
- **F554 — Terminate execution:** Request actual process/run termination where supported and keep unsupported targets unresolved.
- **F555 — Revoke or rotate credentials:** Remove underlying access where supported under appropriate authority, with shared-workload impact disclosure.
- **F556 — Prefilled containment scope:** From an action or incident, propose affected runs, grants, connections, and known business impact.
- **F557 — Immediate narrow response:** Let an eligible responder commit an authorized narrow suspension; show additional scope and consequence for wider response.
- **F558 — Containment progress after commitment:** Track the actual response rather than ending with request sent.
- **F559 — Per-path confirmation:** Record request time, operator, control, confirmation evidence/time, in-flight cancellation, failures, unsupported controls, and remaining bypass/credential exposure.
- **F560 — Partial-containment status:** Preserve partial or unknown state while any material known route or in-flight effect remains unresolved.
- **F561 — Future-versus-historical separation:** Confirm stopped new access separately from earlier reads, disclosures, accepted operations, and unresolved impact.
- **F562 — Preauthorized scoped response:** Permit automatic run suspension and dependent-grant revocation inside approved playbooks; wider credential/fleet action needs its own authority.

### 43. Deliberate restoration and recovery

*Source: §§11, 25–26, 31, 38–40, 42.*

- **F563 — Separate restoration workflow:** Record restoration reason and obtain the required authority rather than treating incident closure as permission to resume.
- **F564 — Recovery identity/health checks:** Reverify identity and affected connection health.
- **F565 — Remediation and test checks:** Confirm fixes and required policy or behavior tests.
- **F566 — Residual-authority inspection:** Review remaining grants and waiting approvals before resuming.
- **F567 — Independent recovery review:** Obtain required separate review for restoration.
- **F568 — Narrow restoration cohort:** Restore a bounded cohort or task scope first.
- **F569 — Post-restoration verification:** Verify normal and prohibited actions again before broad expansion.
- **F570 — No stale action replay:** Do not replay denied, expired, missed irreversible, or ambiguous actions automatically when restoring an agent or automation.
- **F571 — Residual impact follow-up:** Keep historical uncertainty assigned after new access is contained.
- **F572 — Fresh reauthorization on recovery:** Treat corrective and compensating work as separately governed actions.

### 44. Organization scope, inheritance, and roles

*Source: §§6, 12, 26, 36–37, 42.*

- **F573 — Flexible organization hierarchy:** Support Organization → Business unit → Team → Environment, with simpler organization/environment setups for small teams.
- **F574 — One accountable owner:** Give each agent one responsible owner while allowing multiple teams to use it through separate grants.
- **F575 — Recorded ownership transfer:** Preserve transfer history without silently transferring authority.
- **F576 — Organization guardrail ceiling:** Establish the maximum permitted authority envelope at organization level.
- **F577 — Narrowing unit/team controls:** Allow business units and teams to further restrict authority.
- **F578 — Environment boundaries:** Add development, staging, and production controls.
- **F579 — Within-envelope grants:** Allocate task authority only inside inherited controls.
- **F580 — Authorized exception paths:** Require designated exception authority without bypassing non-overridable restrictions.
- **F581 — Default functional roles:** Provide Agent Owner, Policy Author, Policy Publisher, Approver, Responder, and Auditor roles.
- **F582 — Author/publisher separation:** Require a different publisher for configured sensitive production changes.
- **F583 — Business/platform authority separation:** Do not equate platform administration with business approval rights or unrestricted sensitive payload access.
- **F584 — Scoped delegated administration:** Support accountable administration at appropriate fleet and organizational scopes.
- **F585 — Platform accountability:** Audit administrators, integrations, privileged changes, evidence access, and response actions under their own permissions.

### 45. Protected changes, emergency authority, and support access

*Source: §§26, 33, 38–42.*

- **F586 — Protected change categories:** Govern policy, tool meaning, consequence-rule, custody-setting, and coverage-exclusion changes that can widen usable authority.
- **F587 — Explicit widening review:** Show broadened permissions and exposure before approving or activating a change.
- **F588 — Control-level distinctions:** Distinguish product invariants, organization-protected controls, environment/target controls, and task grants.
- **F589 — Non-overridable product invariants:** Prevent tenant overrides of product invariants.
- **F590 — Designated organizational change paths:** Change protected controls only through the organization's review or emergency process.
- **F591 — No action-approval bypass:** Prevent an ordinary action approver from overriding protected policy by approving the blocked action.
- **F592 — Independent high-consequence review:** Require assurance-appropriate separate review for sensitive definitions.
- **F593 — Fixed attributable activation:** Make activated versions fixed and attributable to reviewer and publisher.
- **F594 — Bounded emergency access:** Require narrow scope, time limits, authentication, and separate audit; do not waive invariants or fabricate verification.
- **F595 — Compromised-publication response:** Freeze affected promotions, inspect exposed versions, and require independently reviewed restoration when publication/signing authority is compromised.
- **F596 — Signature trust limits:** Do not treat a valid publication signature as proof its issuer was uncompromised.
- **F597 — Task-bound support access:** Request support access for a named task and duration, expose actual scope to the customer, and audit it.
- **F598 — No standing restricted support access:** Give support staff no default access to credentials or restricted transaction payloads.
- **F599 — No silent production publication:** Suggestions and generated drafts cannot silently activate production permission changes.

### 46. Fleet organization and bulk administration

*Source: §§19, 26–27, 36, 38.*

- **F600 — Small-fleet organization:** Organize small deployments around named agents, recent runs, ownership, and simple task templates.
- **F601 — Team/task/environment cohorts:** Organize larger deployments with shared baselines, owner queues, and change summaries.
- **F602 — Accountable large fleets:** Use delegated administration, exception groups, bulk simulation, verified rollout, and aggregated findings.
- **F603 — Shared-cause alert grouping:** Avoid one identical alert per agent while retaining every affected agent's evidence.
- **F604 — Bulk scope previews:** Show affected targets, exceptions, and dependencies before bulk changes.
- **F605 — Coverage-based fleet confidence:** Assess selected effects and paths from verified coverage rather than inventory size.
- **F606 — Scale-oriented views:** Design for the described 10-, 1,000-, and 100,000-agent organizing patterns without treating them as proven capacity benchmarks.

### 47. Notifications, attention levels, and suppression

*Source: §§13, 18, 24, 27, 30–31, 38.*

- **F607 — Searchable telemetry level:** Retain normal reads, expected low-impact denials, and routine checks quietly within configured scope.
- **F608 — Live activity level:** Surface meaningful writes, first sensitive use, and authority changes in grouped streams.
- **F609 — Finding level:** Assign persistent exposure to remediation queues.
- **F610 — Alert level:** Route unexpected sensitive access, control failures, and repeated scope escapes to accountable owners with evidence.
- **F611 — Incident level:** Group related alerts and effects into a single response case.
- **F612 — Immediate interruption level:** Page configured responders for credible ongoing material harm or critical active-path enforcement loss, with uncertainty and containment state.
- **F613 — Evidence-based grouping:** Group by run, identity, authority change, target, or connection failure only when relationships are supported.
- **F614 — Retry-group detail:** Show first/latest attempts, count, target variation, whether any attempt executed, and current response state.
- **F615 — Cross-agent correlation uncertainty:** Group credible shared causes; label mere similarity as a possible relationship.
- **F616 — Test-denial isolation:** Keep expected test denials in test evidence without paging production responders.
- **F617 — Scoped temporary muting:** Mute known benign recurring patterns only within a declared scope and expiry.
- **F618 — Evidence-preserving suppression:** Never delete evidence or disguise a failed control through suppression; keep muted conditions discoverable to owners.
- **F619 — Attention reopening:** Reopen on greater severity, new target scope, confirmed effects, or failed containment.
- **F620 — Actionable notification content:** State what happened, why attention is needed, existing containment, remaining exposure, and next action.
- **F621 — Permission-aware delivery:** Respect data permissions and channel sensitivity in notifications.
- **F622 — Meaningful daily digests:** Summarize decisions, approvals, policy/authority changes, and coverage exceptions with scoped evidence and verified delivery rather than raw call volume.
- **F623 — Quiet automation operation:** Route material automation exceptions to owners while routine successful execution remains inspectable without paging.

### 48. Empty states and operational failures

*Source: §§10, 13, 23, 28, 38, 40–42.*

- **F624 — No-agent guidance:** Offer connection of one supported agent to inspect authority.
- **F625 — No-activity guidance:** Distinguish verified identity with no observed actions from failed collection; suggest a safe test or health inspection.
- **F626 — Empty approval guidance:** Show no requests in selected scope and offer recent decisions or routing health.
- **F627 — Empty incident guidance:** Show no open incidents alongside scope, coverage, and freshness.
- **F628 — Empty search distinctions:** Separate genuinely empty results, absent data, and restricted results; retain the evidence range.
- **F629 — Unknown-classification guidance:** Show sensitivity unknown and offer classification or a conservative boundary.
- **F630 — Unmistakable demonstration labeling:** Prevent demo data from counting as real customer coverage, blocked work, or onboarding proof.
- **F631 — Authorization-unavailable stop:** Prevent sensitive writes, transfers, and protected disclosures without a valid decision; expose the specific configured stop or bounded recovery state.
- **F632 — Bounded degraded-read continuation:** Allow supported low-impact reads during disruption only under a previously authorized explicit time-limited continuation rule; show scope and expiry.
- **F633 — Identity-verification failure:** Permit no new sensitive authority when required identity cannot be verified.
- **F634 — Opaque-semantics failure:** Limit use to named verified controls without unsupported transformations or filtering claims.
- **F635 — Approval-routing failure:** Retain Hold until deadline, then expire, recording missing eligible response and routing failure.
- **F636 — Partial-policy rollout failure:** Identify old-version and unconfirmed targets while retaining previous valid controls where possible.
- **F637 — Missing-effect evidence:** Show unknown execution outcome and require reconciliation before irreversible retry.
- **F638 — Export-destination failure:** Retain delayed/failed delivery and follow approved recovery behavior.
- **F639 — Post-approval resource change:** Revalidate changed preconditions and stop or hold mismatched actions; missing required facts produce Cannot authorize.
- **F640 — Lost-observation failure:** Show the coverage gap and last-seen timestamp.
- **F641 — Owned failure records:** Name accountable connection/platform owner, affected scope, deadline where relevant, and next diagnostic action.
- **F642 — Failure-type distinctions:** Separate policy denial, authentication failure, tool failure, enforcement failure, and uncertain execution so each has its own remedy.

### 49. Progressive disclosure and experience quality

*Source: §§5–6, 8, 13, 19, 29, 34, 37.*

- **F643 — Simple one-agent setup:** Start with owner, identity, tools, template, active grant, and latest run.
- **F644 — Repeated-work controls:** Reveal reusable task grants, recommendations, approval routing, budgets, and simulation as needed.
- **F645 — Team operations controls:** Reveal shared baselines, owner queues, staged rollout, saved investigations, and external response workflows.
- **F646 — Enterprise governance controls:** Reveal inheritance, business units, delegated administration, independent review, evidence collections, and fleet controls.
- **F647 — Always-visible material limits:** Never hide gaps, grant scope, expiry, cumulative budgets, decision reasons, unknown outcomes, or requested-versus-confirmed containment.
- **F648 — Evidence/inference separation:** Label observed facts, deterministic rules, inferred suspicion, and causal hypotheses distinctly.
- **F649 — Safe next-step guidance:** Present developer remedies, approver decisions, and analyst response controls appropriate to current role and evidence.
- **F650 — Task-first presentation:** Organize controls around useful work and consequences rather than raw asset tables, log counts, or unexplained switches.
- **F651 — Consistent comprehension contract:** For permitted runs, blocked actions, approvals, drafts, and partially contained incidents, let users identify actor/principal/authority, action/effect, reason, uncertainty/coverage, and how to act and verify the result.

## Governed automations

### 50. Automation types, inventory, and definition

*Source: §§5, 7–8, 13, 33, 38.*

- **F652 — Agent-work automations:** Start or coordinate existing agents and approved external business workflows.
- **F653 — Security-work automations:** Maintain protection, collect evidence, route decisions, verify controls, and coordinate scoped response.
- **F654 — Shared authority model:** Use the same identity, grant, policy, approval, evidence, and response requirements as manually initiated work.
- **F655 — Versioned automation records:** Store purpose, owner, identity, represented principal, trigger, conditions, steps, and completion criteria.
- **F656 — Permitted execution scope:** Define tools, resources, destinations, and environments.
- **F657 — Grant and issuance ceiling:** Declare a current grant or explicitly authorized maximum future grant issuance.
- **F658 — Automation limits:** Define duration, value, action count, concurrency, human gates, and separation of duties.
- **F659 — Reliability definition:** Specify timeout, retry, reconciliation, and recovery behavior.
- **F660 — Evidence destination definition:** Specify approved evidence and notification destinations.
- **F661 — Sensitive-authority review dates:** Set review or expiry dates for sensitive automation rights.
- **F662 — Automation summary:** Show trigger, owner, execution identity, scope, version, grant requirements, next run, recent outcomes, approvals, and recovery state.
- **F663 — Automation lifecycle controls:** Create from templates, simulate, test, enable, pause, inspect, safely retry, revise, and retire.
- **F664 — Governed coordination boundary:** Invoke existing agents and workflows without requiring an unrestricted agent builder or generic workflow engine.

### 51. Triggers, schedules, authenticity, and replay safety

*Source: §§38, 41.*

- **F665 — Scheduled triggers:** Define named time, timezone, and recurrence.
- **F666 — Event-driven triggers:** Use qualifying events from verified connections.
- **F667 — State-driven triggers:** Start after a condition remains true for a defined duration.
- **F668 — Threshold-driven triggers:** Start when a bounded count, value, or rate crosses a defined threshold.
- **F669 — Manual triggers:** Let eligible users start an approved automation version.
- **F670 — Trigger inspection:** Show source event or scheduled occurrence and how authenticity was established.
- **F671 — Untrusted-content boundary:** Do not let external document text grant authority or redefine trusted triggers.
- **F672 — Timezone-aware next run:** Show the next execution in the configured timezone.
- **F673 — Daylight-saving preview:** Explain skipped or repeated local times.
- **F674 — Missed-run policy:** Define skip or bounded catch-up behavior.
- **F675 — Sensitive-task overlap prevention:** Avoid overlapping executions by default for the same sensitive task.
- **F676 — Duplicate-event protection:** Prevent duplicate or replayed events from duplicating supported irreversible effects.
- **F677 — Trigger ancestry:** Retain ancestry across related executions for loop analysis.

### 52. Automation editor and draft validation

*Source: §§8, 38.*

- **F678 — Automate-a-task entry point:** Start creation from useful templates.
- **F679 — Readable workflow outline:** Define When, If, Under authority, Do, Wait when, If work fails, and Finish when.
- **F680 — Ordered steps and branches:** Make step ordering, branch conditions, and terminal outcomes explicit.
- **F681 — Plain-language workflow summary:** Present trigger, task scope, limits, human gates, uncertainty handling, and notification policy in one inspectable summary.
- **F682 — Natural-language workflow drafting:** Propose workflows from text while making the inspected structured definition control execution.
- **F683 — Owner/identity checks:** Flag missing accountable owner or verified execution identity.
- **F684 — Unbounded-scope checks:** Flag unbounded resource selection or budgets.
- **F685 — Branch-completion checks:** Flag missing deadlines or terminal outcomes.
- **F686 — Irreversible-step checks:** Require retry and reconciliation rules for irreversible work.
- **F687 — Approval-route checks:** Flag gates without an eligible approver.
- **F688 — Cycle/loop checks:** Detect dependency cycles and event loops.
- **F689 — Unsupported-capability checks:** Flag missing enforcement, cancellation, response, or verification support.
- **F690 — Evidence-based completion checks:** Reject request sent as completion unless delivery is actually the defined task.

### 53. Useful automation templates

*Source: §§30–31, 38.*

- **F691 — Bounded task launch template:** On verified ticket or approved schedule, establish fresh bounded task authority and start an existing agent; broader access requires a separate grant workflow.
- **F692 — New-agent intake template:** Find candidate owners, inspect tools, propose baselines, and run safe tests; humans confirm identity and sensitive production access.
- **F693 — Approval routing template:** Find eligible approvers, deliver requests, remind, and escalate within deadline; record resolution and subsequent action outcome.
- **F694 — Grant lifecycle template:** Notify as needed, expire or revoke authority at expiry/task close, confirm affected paths, and require fresh review for extension.
- **F695 — Scoped incident containment template:** Match verified approved criteria, suspend affected runs, revoke permitted dependent grants, preserve evidence, and verify per-path response.
- **F696 — Human exception branch:** Create a case when response criteria do not match; escalate partial/unknown containment and require human review of historical effects and recovery.
- **F697 — Coverage recovery template:** Diagnose within authority, pause sensitive launches, assign owners, and require passing coverage retests before resuming.
- **F698 — Least-privilege review template:** Draft restrictions from scheduled evidence and simulate impact; production publishing remains an eligible human change workflow.
- **F699 — Audit and digest template:** Gather permitted evidence, redact, generate reports, and verify delivery; broader access or new destinations require review.
- **F700 — Approved business workflow template:** Call permitted tools or launch existing workflows after verified events, apply task-specific gates, and confirm actual business results.

### 54. Authority at every automation execution

*Source: §§1, 10, 12, 26, 38–43.*

- **F701 — Definition-versus-action approval:** Enabling a workflow approves its definition, not unlimited future actions.
- **F702 — Current trigger and owner checks:** Reverify trigger, owner, identity, represented principal, and approved scope for every execution.
- **F703 — Current grant establishment:** Obtain or verify a valid grant inside the automation's ceiling.
- **F704 — Explicit automated issuance:** Issue fresh grants automatically only when an authorized principal explicitly approved targets, ceiling, duration, and renewal conditions.
- **F705 — Per-step runtime decisions:** Evaluate every covered step against current policy and action meaning.
- **F706 — Final human/precondition recheck:** Revalidate approval, authentication, facts, limits, and consent before consequential steps.
- **F707 — No former-owner impersonation:** Do not reuse invalid owner authority or expired human approval.
- **F708 — No self-expansion after denial:** Do not silently acquire more access or destinations to complete blocked work.
- **F709 — Material automation change review:** Require impact review and republication for identity, scope, budget, destination, or grant-ceiling changes.
- **F710 — Same custody and coverage contract:** Apply current access controls, reviewed meaning, equivalent-route coverage, and verification to automatic effectful steps.
- **F711 — No protocol bypass:** Do not evade denial by selecting a different tool name or protocol causing the same effect.
- **F712 — Pre-enable effect inspection:** Show direct/downstream effects, dependency effect states, required fresh facts/classifications, custody/routes, approvals/authentication, and verification/uncertainty behavior.
- **F713 — Affected-step invalidation:** Stop dependent steps after package quarantine, expired coverage, revoked identity, or changed conditions; independent healthy work proceeds only with validated separation.
- **F714 — Execution attribution:** Trace every action to trigger, workflow version, identity, grant, policy, and evidence.

### 55. Automation execution inspector and completion states

*Source: §§8, 13–14, 38, 42.*

- **F715 — Execution detail:** Show trigger/schedule, version, initiating principal, execution identity, grant lineage, current step, and elapsed time.
- **F716 — Step transaction history:** Show each step's decision, outcome, attempts, and supporting evidence.
- **F717 — Child/external workflow references:** Link launched agents and external workflows to the execution.
- **F718 — Budget and human-gate status:** Show approved/remaining budget, waiting decisions, and expiry.
- **F719 — Final-result detail:** Show partial effects, unresolved work, and completion evidence.
- **F720 — Execution completion vocabulary:** Distinguish Succeeded, Partially completed, Failed, Cancelled, Waiting, and Needs reconciliation.
- **F721 — Evidence-based success:** Mark Succeeded only when defined completion evidence exists; accepted requests and delivered triggers are insufficient unless delivery is the intended result.
- **F722 — Recovery drill-down:** Open workflow graph, run timeline, authority lineage, affected resources, and delivery evidence from the same execution.

### 56. Automation retries, partial completion, pause, and loop prevention

*Source: §§10, 25, 38, 42.*

- **F723 — Bounded retry policy:** Set maximum attempts, interval bounds, and total deadline.
- **F724 — Safe-operation retries:** Retry only when supported operation semantics make another attempt safe.
- **F725 — Stable step-action identity:** Preserve identity where supported to avoid duplicate effects.
- **F726 — Unknown irreversible outcome stop:** Require reconciliation before retrying payments, deletion, or external sends with unknown outcome.
- **F727 — Partial-completion accounting:** Show which steps changed the world and which did not.
- **F728 — Explicit compensation:** Use supported compensating operations with separate authorization and residual-consequence disclosure.
- **F729 — Pause semantics:** Stop new triggers according to declared policy without implying active executions have stopped.
- **F730 — Pending-trigger disposition:** State whether triggers are discarded, queued within bounds, or expire.
- **F731 — Separate active cancellation:** Make stopping active executions an additional scoped action with its own evidence.
- **F732 — Resume revalidation:** Recheck authority, policy, resource conditions, approvals, and required coverage before continuing.
- **F733 — No automatic irreversible catch-up:** Do not replay missed irreversible work automatically.
- **F734 — Self/reciprocal loop detection:** Detect workflows repeatedly triggering themselves or each other using ancestry.
- **F735 — Loop action limits:** Apply per-event and per-period bounds.
- **F736 — Grouped loop issue:** Open one accountable grouped issue when a loop is stopped.
- **F737 — Distinct pause/cancel/revoke evidence:** Show the different scope and verified effects of each control.

### 57. Automation tests, simulation, shadowing, and rollout

*Source: §§11, 38.*

- **F738 — Authority-complete draft testing:** Test normal, denied, timeout, duplicate-event, and partial-outcome scenarios.
- **F739 — Historical trigger simulation:** Show prospective steps, decisions, missing context, and expected completion requirements.
- **F740 — Safe trigger shadowing:** Observe real triggers without invoking effectful external steps.
- **F741 — Explicit real diagnostics:** Label separately permitted diagnostic operations as real work, not shadow effects.
- **F742 — Volume and approval forecasts:** Preview task volume, approver demand, budgets, and resource reach.
- **F743 — Bounded activation:** Enable a limited cohort or schedule window first.
- **F744 — Result verification before expansion:** Verify actual outcomes before widening deployment.
- **F745 — Simulation uncertainty:** Do not guarantee how external agents/workflows would react to different inputs; retain missing-context categories.
- **F746 — No dangerous shadow probing:** Never call a dangerous tool merely to learn what would happen.

### 58. Automation exposure and owner confidence

*Source: §§13, 17, 19, 36, 38–41.*

- **F747 — Automation-as-actor exposure:** Include automation identities as well as the agents they launch.
- **F748 — Current-versus-future authority:** Separately show active execution grants and issuance ceilings for future runs.
- **F749 — Pre-enable blast-radius preview:** Show resources, consequential operations, spend, record/recipient/concurrency maxima, child delegation, shared credentials, approvals, restrictions, uncovered routes, uncertain side effects, and triggered workflows.
- **F750 — Restriction impact comparison:** Compare before/after exposure and expected business disruption.
- **F751 — Concise owner status:** Show enabled/paused state, next timezone-specific run, latest verified outcome, maximum task budget, human thresholds, and reconciliation backlog.
- **F752 — Owned automation exceptions:** Route approval expiry, lost coverage, failed containment, authority drift, and unresolved irreversible work to accountable owners.
- **F753 — Useful-work measurement:** Measure completed work and necessary interventions rather than treating trigger count as success.
- **F754 — No inactivity-based low-risk claim:** Quiet schedules can retain substantial issuance authority and latent exposure.

## Supported work, quality measures, and boundaries

### 59. Supported resource domains and concrete governed workflows

*Source: §§2, 10–11, 23, 30–31, 36, 43.*

- **F755 — Source/development operations:** Govern supported repository reads, branch preparation, PR creation, merges, settings, and workflow changes; distinguish direct writes from deployment consequences.
- **F756 — Cloud/infrastructure operations:** Govern supported provisioning, deployment, access changes, deletion, and service operations with exact environment, resources, prerequisites, and cancellation limits.
- **F757 — Business-application operations:** Govern customer updates, account changes, and ticket resolution under stable record scope and represented-user authority.
- **F758 — Finance operations:** Govern supported refunds, payments, and budgeted purchasing with amount, units/currency, recipient/account, cumulative limits, independent approvals, and settlement meaning.
- **F759 — Data operations:** Govern query, export, transformation, and sharing with classifications, selected targets, destinations, and actual integration filtering support.
- **F760 — Communication operations:** Govern email, messaging, notifications, and external publishing with recipient sets, content scope, delivery evidence, and irreversibility limits.
- **F761 — Runtime/host operations:** Govern supported shell, filesystem, browser, CLI, and child-agent operations with explicit channel coverage and capability evidence.
- **F762 — Support resolution workflow:** Allow ticket-linked reads/updates and bounded refunds, hold above approval thresholds, deny deletion/unrelated data/bulk export outside scope, and route legitimate corrections.
- **F763 — Treasury workflow:** Review exact payee, account, currency, amount, cumulative exposure, recent bank changes, independent approvals, and settlement evidence; deny amounts outside grant ceilings even with approval.
- **F764 — Read-only diagnostic workflow:** Permit scoped production diagnostics while denying production deletion and other changes.
- **F765 — Aggregate-data workflow:** Permit approved aggregate reporting when supported and reject unrestricted row access outside authority.
- **F766 — Research/disclosure workflow:** Allow bounded dataset reads and internal summaries; block covered unauthorized external exports, link preceding reads, and investigate residual bypass exposure.
- **F767 — Coding-to-production workflow:** Govern vulnerability-task reads, branch/PR work, exact reviewed merge, supported deployment consequences, independent release gates, one-merge budgets, and actual production revision verification.
- **F768 — Workflow-specific coverage:** State each integration's supported actions, constraints, verification, and exclusions; broad domain support is not universal control.

### 60. Capability evidence and product outcome measures

*Source: §§10, 13, 21–22, 30–31, 35–38, 43.*

- **F769 — Functional evidence:** Show that permitted work achieves the stated result.
- **F770 — Boundary evidence:** Demonstrate unauthorized-route blocking and identify uncovered equivalent routes.
- **F771 — Recovery evidence:** Show described behavior for timeout, retry, partial effects, revocation, and restoration.
- **F772 — Explanation evidence:** Link decisions to exact authority, policy, meaning, and facts.
- **F773 — Operational evidence:** State freshness, supported continuity, responsiveness, and operating limits.
- **F774 — Protected-workflow setup measurement:** Track time to useful, verified protected work.
- **F775 — Decision/investigation measurement:** Track time to understand decisions and reconstruct incidents.
- **F776 — Containment measurement:** Track time from suspicious activity to verified containment.
- **F777 — Scope-qualified coverage measurement:** Track selected consequential effects with reviewed meaning and current coverage.
- **F778 — Bypass remediation measurement:** Track equivalent routes discovered and closed with evidence.
- **F779 — Change-assurance measurement:** Track policy/package changes with reviewed impact evidence.
- **F780 — Business-friction measurement:** Track false blocks, exceptions, approval burden, and abandonment by workflow.
- **F781 — Outcome-assurance measurement:** Track verification support, unresolved effects, and reconciliation age.
- **F782 — Automation effectiveness measurement:** Track useful work completed and necessary human interventions.
- **F783 — Operating-effort measurement:** Track integration setup, ongoing review, and recovery effort.
- **F784 — Existing-control comparison:** Compare results with configured existing controls and record incremental protection/investigation value.
- **F785 — No volume-based value proxy:** Do not use raw events, agent count, trigger count, or global safety scores as proof of protection or value.

### 61. Explicit product boundaries and prohibited shortcuts

*Source: §§1, 4–5, 10–11, 19, 23, 25–26, 33, 36, 39–42.*

- **F786 — Connected-enforcement boundary:** Govern only connected supported enforcement points and disclose uncontrolled tools, credentials, routes, and exclusions.
- **F787 — No general identity replacement:** Preserve existing human identity sources.
- **F788 — No generic log-warehouse scope:** Organize evidence around attributable actions and consequences rather than unrestricted log collection.
- **F789 — No prompt correctness guarantee:** Do not claim proof that every instruction, plan, or model output is safe.
- **F790 — No full agent-building environment:** Customers bring agents; governed coordination does not imply an unrestricted builder or orchestration platform.
- **F791 — No universal rollback:** Completed transfers, deletion, and disclosure may need external recovery and may be irreversible.
- **F792 — No mandatory surveillance capture:** Do not require raw conversations or hidden model reasoning for core protection.
- **F793 — No unconstrained autonomous security commander:** Suggestions and automations cannot silently widen their own response authority.
- **F794 — No hidden policy activation:** Production permission changes require the governed publication workflow.
- **F795 — No denial-driven privilege expansion:** Only authorized grant or change workflows can increase authority.
- **F796 — No universal command rewriting:** Do not guess safe shell replacements.
- **F797 — No unrelated threat-feed dashboard:** Use external threat/risk signals only when they inform authority, decisions, or investigation.
- **F798 — No decorative exposure universe:** Use evidence-scoped graphs that answer specific questions and provide tables/timelines when clearer.
- **F799 — No trust score as permission:** Scores cannot replace identity, grants, constraints, and required evidence.
- **F800 — No destructive automatic response by default:** Restrict automatic response to explicit preauthorization; suspicion alone cannot justify silent organization-wide revocation.
- **F801 — No unsupported protection claims:** A connection, graph, successful demonstration, short-lived credential, signature, or success response alone cannot establish full coverage, custody, effect, integrity, or compliance.
- **F802 — No invented assurance:** Missing, stale, unknown, partial, pending, conflicting, and unverifiable states remain visible and owned until resolved.

### Source terminology reference

The source gives the following formal names for records used by these features. These are alternative names for the same concepts, not additional permissions or separate product modules.

| Customer-visible concept | Formal source term | Relevant feature groups |
| --- | --- | --- |
| Task grant | `AuthorizationEnvelope` / `DelegationGrant` | 04–05, 54 |
| Action definition | `ActionIR` | 07, 28–29 |
| Reviewed tool package | `SemanticPackage` | 28–29 |
| Downstream consequence | `ConsequenceIR` | 30 |
| Protection boundary | `EnforcementBoundary` | 31–33 |
| Coverage evidence | `CoverageSnapshot` / `AuthorityPath` | 32–33 |
| Transaction evidence | `DecisionReceipt` / `ExecutionReceipt` / `EffectReceipt` | 34–40 |

## Source coverage map

Every numbered section in the revised source is accounted for below. Sections 1–43 map to existing product features; §44 maps to the separate engineering appendix. Scenario requirements are included as reusable features rather than presented as proof of implementation. Feature groups consolidate repeated requirements while retaining specific behavior and limits.

| Source section | Source subject | Feature groups |
| --- | --- | --- |
| 1 | Product thesis, transaction identity, scope, authority-to-effect | 01, 03–07, 31–34, 54, 61 |
| 2 | Category and initial bounded-work problem | 01, 04, 59 |
| 3 | Full product description | 01–61 |
| 4 | Product exclusions | 03, 18, 39, 50, 61 |
| 5 | Core principles | 01, 04, 06–07, 17, 32, 49–50, 61 |
| 6 | Primary users | 01, 44, 49 |
| 7 | Core objects and formal/plain-language concepts | 01, 04–05, 28, 30, 32, 34, 50 |
| 8 | Seven surfaces and shared interaction rules | 01–02, 06, 12, 14, 16–19, 21, 23, 26, 42, 50 |
| 9 | Inventory, verified identity, discovery, drift | 02–03, 29, 32 |
| 10 | Runtime decisions, limits, sequences, retries, exact states | 06–13, 34–37, 48, 59 |
| 11 | Templates, policies, tests, simulation, rollout, exceptions | 14–16, 38, 43, 57 |
| 12 | Delegation and lineage | 03–05, 09, 20, 31 |
| 13 | Live awareness and automation exceptions | 17–18, 47, 58 |
| 14 | Run/session inspector | 18–19, 22, 55 |
| 15 | Unified investigation and closure | 19, 40, 42 |
| 16 | Exact approvals, authenticity, channels, overload | 07, 11–13, 39 |
| 17 | Risk, reach, blast radius, dependencies | 20–22, 31, 36, 42, 58 |
| 18 | Posture and evidence-based remediation | 02, 21, 47 |
| 19 | Activity, authority, coverage, causality, graphs, charts | 06, 18, 20–23, 30, 32–33, 39, 42, 58 |
| 20 | Universal search and permission-scoped interpretation | 01, 19, 23, 39–40 |
| 21 | Developer onboarding and production readiness | 24 |
| 22 | Security onboarding and dependency-led expansion | 25 |
| 23 | Capability integrations, custom definitions, packages, signals | 08, 26–33, 37, 41, 48 |
| 24 | SIEM/SOAR exports, delivery, response, incident sync | 39–42 |
| 25 | Response, confirmation, in-flight limits, recovery | 11, 37, 41–43 |
| 26 | Organization, inheritance, roles, protected change, audit, fleet | 04, 12, 14–16, 39–40, 43–46 |
| 27 | Attention levels, grouping, suppression, channel privacy | 17, 23, 39, 47 |
| 28 | Empty states, failure behavior, owned operational gaps | 07, 16, 24–25, 39, 41, 48 |
| 29 | Progressive disclosure and non-hidden material limits | 01, 49 |
| 30 | Support day, tool updates, grant correction, rollout, digests | 09, 16–17, 28, 47, 53, 59 |
| 31 | Export incident, automated containment, residual exposure, recovery | 19–20, 33, 40–43, 53, 59 |
| 32 | Connected experience and differentiation | 01, 04, 06, 12, 15–16, 18–20, 42 |
| 33 | Features and shortcuts deliberately excluded | 39, 45, 50, 61 |
| 34 | Defining user outcomes | 02, 06, 12, 15, 24, 28, 42, 49 |
| 35 | Fifteen non-negotiable capabilities | 02–16, 19, 26–45, 50–58 |
| 36 | Complete scope, domains, capability evidence, outcome metrics | 01, 20, 26–33, 44, 46, 58–61 |
| 37 | Experience principles and comprehension test | 01, 06, 44, 49 |
| 38 | Full automation creation, authority, execution, recovery, rollout | 13, 17–18, 20, 22, 30, 34, 40, 47, 50–58 |
| 39 | Access modes, custody, exact execution, revocation, assurance | 03, 07–09, 11, 31, 42, 54, 61 |
| 40 | Reviewed meaning, downstream rules, behavior assurance and drift | 08, 12, 28–30, 37, 45, 54 |
| 41 | Current coverage, equivalent-route discovery, invalidation, closure | 22, 31–33, 51, 54, 58 |
| 42 | Receipts, verification, replay, integrity, retention, packs | 11, 22, 34–40, 43, 54, 61 |
| 43 | Coding task through exact merge and production verification | 05, 12, 19, 22, 30–37, 59 |
| 44 | Secure development guidance from both screenshots; engineering gates and evidence | Appendix A, SG01–SG14; companion engineering plan |

## Appendix A — Secure engineering requirements

*Source: specification §44 and [GATES_AND_REVIEW.md](../security/GATES_AND_REVIEW.md) (absorbed the secure engineering plan, version 1.0, October 7, 2026); both supplied guidance screenshots.*

These are mandatory controls for building PantherClaw, separate from its 802 intended product features. The original catalog did not fully capture this development guidance. Product identity, evidence, runtime approval, tool-package review, and coding-agent workflows provide related requirements but do not replace a secure engineering process.

| ID | Required engineering behavior | Principal gate / evidence |
| --- | --- | --- |
| SG01 | Define and review explicit security constraints before coding; provide them to generating models. | G0: approved scope, baseline, and generation brief. |
| SG02 | Threat-model assets, boundaries, attack surfaces, likely adversaries, abuse paths, mitigations, and residual risks. | G0/G4: versioned threat model and reviewed updates. |
| SG03 | Choose and document secure layered/component patterns, least privilege, zero-trust assumptions, and strong input validation boundaries. | G0/G1: architecture decisions, enforcing components, boundary tests. |
| SG04 | Explicitly specify human, workload, and service authentication and lifecycle requirements. | G0/G1: method baseline and identity/session tests. |
| SG05 | Explicitly specify encryption standards, reviewed libraries, and key management. | G0/G2: approved parameters and configuration/key-control evidence. |
| SG06 | Explicitly specify security logging, redaction, access, retention, integrity, and failure behavior. | G0/G2: event schemas and data-handling tests. |
| SG07 | Explicitly specify dependency sources, pinning, provenance, updates, vulnerability handling, and inventory. | G0/G1/G2/G4: policy, inventory, scans, and update review. |
| SG08 | Use bounded AI-assisted scaffolding from approved constraints; subject generated changes to the same controls as other changes. | G1: exact brief, diff/revision, assumptions, and tests. |
| SG09 | Continuously scan source, dependencies, secrets, and applicable infrastructure/container/runtime surfaces; test sensitive product failure paths. | G1/G2/G4: scheduled and change/release check results with scope and owners. |
| SG10 | Use models as reviewers: identify insecure patterns, safer alternatives, attack vectors, and evidence-based verification steps. | G1: structured findings tied to code and candidate revision. |
| SG11 | Use independent multi-model reviewer passes and preserve disagreements for human adjudication. | G1: actual reviewer identities/configurations, both reviews, reconciliation. |
| SG12 | Require human review at every critical development stage; independent review for security-critical code and release approval. | G0–G4: accountable sign-offs bound to scope/revision. |
| SG13 | Compare applicable code against a selected, versioned OWASP Top 10 and/or CWE category baseline. | G0/G1/G2: selection, applicability map, findings, and control evidence. |
| SG14 | Track finding resolution, permitted exceptions, and requirement completion with retained evidence. | All gates: owners, test-backed closure, expiry, and truthful status. |

Detailed acceptance criteria, review briefs, unresolved design decisions, and the screenshot coverage audit are maintained in the companion plan. Product IDs remain F001–F802; engineering IDs remain SG01–SG14.

**Current status:** All visible guidance from both screenshots is now written into the three-document set. Engineering implementation and verification remain Planned / not evidenced. No scans, development approvals, threat-model decisions, or production readiness are asserted by adding this appendix.
