# Explanations

## Purpose

Every decision can be explained, for "why can" and "why can't" alike: which grants and policies applied, which
statements decided, which conditions held or failed and which key was missing (AUTHZ-11.5). This note explains explain
mode, the switch on the one decision path that records the evidence an explanation needs, and the `Explanation` it
returns: what it holds, how it renders and what it never holds. The `authorization:why` command that prints one for a
named subject is the second part of BL-68.

## Invariants

1. **One path (D22, N89).** `AuthorizationManager::explain()` decides its check through `CheckBatch::decideOne()`, as
   `check()` does, with the batch's explain switch on. The batch decides it through `DecisionPipeline::explaining()`,
   a clone of the pipeline holding a fresh `Evaluation\EvidenceRecorder` for that one check. The stages, the sources
   and the verdict are the ones `check()` gets; the decision is recorded as the last decision and reported with its
   `DecisionEvaluated`, as any check is. A preview's `explain()` takes the preview's path, admitted, recorded and
   reported as its `check()` is.

2. **An everyday check is unchanged.** No other caller turns the switch on. Without it the pipeline makes no recorder,
   the check's context records nothing, the grants are resolved as they always are, through the resolution cache, and
   the decision carries no evidence. Its only additions are cheap and taken on construction: each statement works out
   once the `${…}` references its operands and resource patterns name (`Statement::$dependencies`), and each step of a
   statement assessed carries them, so `Decision::keys()`, and the decision events, name them beside the condition
   keys.

3. **Complete for the path taken, and nothing else (N88).** An explanation holds the evidence of every stage the
   decision reached, in order, and marks the stages after the deciding one that it never reached as not evaluated. An
   allow marks none, since every stage that could refuse it let it through. Nothing is evaluated hypothetically, so an
   explicit deny never says whether the caps or the allows would have let the check through.

4. **What decided it.** The deciding statements, every one when several did (several denies, several allows, the
   allows an insufficient authentication names), or, when none did, the cause: the guardrails, boundaries, session caps
   or administration constraints that refused at the deciding stage, by name, the permission held, or the reason alone
   (an early refusal, whose trace is empty, an unreadable document, a failed condition, no match).

5. **Each condition test on its own.** Through an explaining context (`CheckContext::explain()`), each test a
   statement makes is recorded as a `ConditionResult`: its key, its operator, whether `_if_exists` lets a missing key
   pass, whether the key was missing, its outcome (`ConditionOutcome`) and the keys of its operand's references that
   could not be resolved. The outcome keeps the statement's own: a missing key passes under `_if_exists` and `null:
   true`, fails under `null: false`, and is otherwise `missing`; a null the test does not accept is `null`, since every
   operator but `null` tests it; a value of the wrong type is `wrong_type`; an unresolved operand `unresolved`; a
   substituted operand of the wrong type, or a requirement that cannot be checked, `undecidable`; a malformed test
   `invalid`. Two tests of one key stay apart. The statement's `MatchOutcome` and its condition keys are the ones an
   everyday assessment gives, so a definite failure still decides a deny's conjunction over an undecidable test. The
   resource patterns' unresolved references are kept beside the tests, on the step of the statement whose patterns read
   them, a statement whose target did not match included, so none is claimed by a later statement. The context notes
   each unresolved reference as the interpolator meets it, every one of a string, not only the first, though only the
   first is logged and a later reference into a namespace no test has read is never looked up, so no provider is asked
   (`CheckContext::noteIfUnresolved()`). The statement takes them after each test, so telling the outcome reads
   nothing new, and it notes its tests with the context, which the evaluator takes into the statement's step;
   `MatchResult` carries none, so an everyday assessment builds no more than it did. A string operator's substituted
   operand that is empty or holds a NUL byte, against a string value it can test, is `undecidable`, the operand's
   doing, never `wrong_type`.

6. **Grant provenance, matched to what decided (N89).** For an explained check, `Resolvers\GrantProvenanceResolver`
   decides the permission held and the policies of the principal and its identity from what an everyday check decides
   from: the grantee's entry in the resolution cache, when the cache holds one. Where each grant came from is read
   afresh from the rows a resolution reads, with the grant row's tenant and application, the role held and each
   ancestor up to the role that carries the grant (`RoleGraph::pathsOf()`, `permissionsByRole()`,
   `RolePolicies::attachedTo()`), in no more queries than the resolution of the names and asking no attribute
   provider. On a cold cache the check decides from those rows, as a resolution would, and keeps nothing in the cache.
   A grant is reported only as the rows support what decided: the permission held by its grants of that name, a
   policy by its attachments to that grantee; one the rows no longer give, a stale cache entry say, is `unavailable`,
   never guessed. An identity of the other kind gives its deny statements alone, which never allow, so none of its
   attachments is reported. A grantee whose `getPermissions()` or `getPolicies()` is its own, a policy store, a policy
   resolver bound in place of the default and a `withPolicies()` override cannot say where a grant came from: each is
   asked as an everyday check asks it, and its grant recorded as `unavailable`. A resource policy is named by the
   resource it is attached to, its attachment's scope not recorded. A further check the administration stage makes is
   never explained, so it never overwrites the check's own evidence.

7. **What it asked.** The batch adds to an explained decision's evidence an `ExplanationRequest`: the action, the
   resource's identifier, the subject, its identity and the previewer, the scope the check was asked in and the scope
   it was decided in, from the provenance #123 records. It is captured as the check is made, never read back.

8. **An immutable projection.** `Decision::explain()` returns `Explanation::of($decision)`, built from the decision
   alone. Nothing is evaluated, read, recorded or dispatched to build or render it.

9. **Renderers.** `toText()` (`Evaluation\ExplanationText`) writes every name escaped as a JSON string is: `<`, `>`,
   `&` and non-ASCII characters as `\uXXXX`, a quote and a backslash with a backslash, and a control character as its
   JSON escape, `\b`, `\f`, `\n`, `\r` and `\t` in short and any other as `\uXXXX` (`\u0001` say), so no name can
   inject markup, control characters or a line of its own. `toArray()` and `jsonSerialize()` write one stable schema,
   `version: 1`: the verdict, `decided_by`, the steps grouped by stage, `not_evaluated`, the grants, the requirements
   by part names and unmet parts, the keys, the missing keys, the request and whether the evidence was recorded.

10. **Never a value (AUTHZ-8.8).** No context or attribute value, operand, interpolated string, model, raw context,
    session, proof or fingerprint reaches an explanation, its text or its schema; a requirement is named by its parts,
    never its options. Names still disclose how the policies are built, so an explanation is for those allowed to see
    them, and another subject's goes through a preview (N85).

11. **A stored decision explains with what it has.** A decision made without explain mode, the last decision of an
    everyday check say, explains with its verdict, its cause, its trace, the stages it never reached and its
    requirements. The condition tests of an assessed statement, the missing keys, the grants and the request are
    `not recorded (explain mode off)`, never re-evaluated.

## Success Path

1. `Authorization::for($user)->explain('posts:publish', $post)` builds a `CheckInput` and asks the batch, with the
   explain switch on, to decide it for the subject.
2. The batch decides it through `explaining()`: the pipeline admits the check, gathers the sources with the recorder,
   which resolves the policies with their provenance and marks the context as explaining, and weighs them.
3. The evaluator records each step, each assessed statement's carrying its tests; at the allow stage the permission
   callback resolves the permission held with its provenance and notes it.
4. The pipeline returns the decision with the evidence of the grants that allowed it; the batch adds the request,
   records the decision and dispatches its event.
5. The manager returns `$decision->explain()`, which the caller renders as text or JSON.

## Failure / Edge Cases

- **An early refusal.** A missing or inactive subject, an unidentifiable resource or one outside the scope is explained
  with an empty trace, its reason as its cause and every later stage not evaluated.
- **An unreadable document.** A policy, boundary or guardrail that cannot be read denies as `invalid_policy` at the
  deny stage, with no statement, as it does without explain mode.
- **A check that throws.** `explain()` throws what `check()` throws, a preview's refusal included, and explains
  nothing.
- **A warm cache.** An explained check decides from the cache, as an everyday check does, but still reads the grant
  rows afresh for where each grant came from, once a permission is found held or the grantee has a policy, where an
  everyday check reads none; it reads no more than a resolution of the names does. On a cold cache it reads no more
  than an everyday check, and keeps nothing in the cache.
- **A stale cache.** A grant the cache still holds that the rows read afresh no longer give is reported as
  `unavailable`; the verdict is the one an everyday check gets from the same cache.

## Implementation Anchors

- `AuthorizationManager::explain()` -- the check in explain mode, and its explanation.
- `Evaluation\CheckBatch` -- the explain switch, and the request added to the evidence.
- `Evaluation\DecisionPipeline::explaining()`, `decide()`, `sources()` -- the recorder, the explained policies and
  permission, and the evidence on the decision.
- `Evaluation\EvidenceRecorder` -- the provenance noted while the check is decided, and the evidence of the grants that
  allowed it.
- `Resolvers\GrantProvenanceResolver`, `Resolvers\DefaultPolicyResolver::explainedPoliciesFor()` -- the grants with
  their provenance.
- `Evaluation\CheckContext::explain()`, `noteUnresolved()`, `noteAssessment()`, `ContextInterpolator` -- the unresolved
  references and the tests each statement notes.
- `Evaluation\Statement`, `Evaluation\ConditionClassifier`, `Evaluation\ConditionResult` -- each test's outcome.
- `Evaluation\Decision`, `DecisionEvidence`, `GrantProvenance`, `ExplanationRequest` -- the evidence a decision carries.
- `Evaluation\Explanation`, `Evaluation\ExplanationText` -- the projection and its renderers.

## Authoritative Tests

- `Explanations\AuthorizationManagerTest` (Feature) -- direct, role, inherited and identity grants, policy and
  resource-policy allows, unavailable custom sources, early refusals, explicit denies with later stages not evaluated,
  caps as causes, invalid policies, insufficient authentication, each condition outcome and the missing keys, the
  recording and the absence of side effects when rendering, no extra queries or provider calls, and a preview's
  admission and recording.
- `Explanations\ParityPropertyTest` (Integration) -- the verdicts, traces and requirements of explain mode are those of
  `check()` over random scenarios.
- `Resolvers\GrantProvenanceResolverTest` (Feature) -- the provenance of each kind of grant, the same names and
  policies as the resolution, no more queries, a warm cache deciding, a stale grant `unavailable`, and a cold cache
  keeping nothing.
- `ExplanationTest`, `ExplanationTextTest`, `ConditionClassifierTest`, `EvidenceRecorderTest` (Unit) -- causes, stages
  not evaluated, the schema, the escaping, each typed outcome, and the sentinels that no value reaches an explanation.
- `SingleCheckBudgetTest`, `ConditionEvaluationBudgetTest`, `EvaluatorThroughputTest` (Performance) -- the everyday
  path's cost.

## Change Triggers

- `authorization:why` (BL-68 part 2) prints an explanation for a named subject; it must keep this projection and its
  schema, and never print a value.
- A new stage must be placed in `DecisionStage`'s order, which the stages not evaluated follow.
- A new grant source must say where its grants come from, or be recorded as `unavailable`.
- A change to the schema bumps `Explanation::VERSION`.
