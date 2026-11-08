<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the explanation value object (AUTHZ-11.5, N88): what decided a
 * decision, the stages it reached and never reached, and its stable schema,
 * projected from the decision alone and never carrying a value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Explanation::class)]
final class ExplanationTest extends TestCase
{
    /** @var string A value a check reads, which no explanation may carry. */
    private const string SECRET = 'sentinel-value-91c2';

    /**
     * An explanation carries what the decision decided, and the decision
     * explains itself as one.
     *
     * @return void
     */
    public function testOfProjectsTheDecision(): void
    {
        $statement    = new StatementReference('p', 0);
        $trace        = [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, ['input.a' => true])];
        $decision     = Decision::allow(DecisionStage::ALLOW, [$statement], $trace);
        $explanation  = Explanation::of($decision);
        $unmet        = [new UnmetRequirement(new AuthenticationRequirement(['multifactor' => null]), ['multifactor'])];
        $insufficient = Explanation::of(Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [$statement], $unmet));

        self::assertTrue($explanation->isAllowed());
        self::assertNull($explanation->reason);
        self::assertSame(DecisionStage::ALLOW, $explanation->stage);
        self::assertSame([$statement], $explanation->statements);
        self::assertNull($explanation->cause);
        self::assertSame($trace, $explanation->steps);
        self::assertSame(['input.a'], $explanation->keys);
        self::assertFalse($explanation->isDetailed());
        self::assertNull($explanation->evidence);
        self::assertEquals($explanation, $decision->explain());
        self::assertFalse($insufficient->isAllowed());
        self::assertSame($unmet, $insufficient->requirements);
    }

    /**
     * A cap that refused is named as the cause, each that refused at the
     * deciding stage and none from another stage.
     *
     * @return void
     */
    public function testACapThatRefusedIsTheCause(): void
    {
        $guardrail = Policy::fromArray(['name' => 'rail', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]])->withId('4');
        $boundary  = Policy::fromArray(['name' => 'cap', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]])->withId('9');
        $evaluator = new PolicyEvaluator;

        $guarded = Explanation::of($evaluator->evaluate([], 'posts:edit', null, [], [], null, [$guardrail]));
        $bounded = Explanation::of($evaluator->evaluate([], 'posts:edit', null, [], [$boundary]));
        $capped  = Explanation::of($evaluator->capped(new SessionCaps([['credential', ['posts:read']], ['capped', ['posts:*']]]))->evaluate([], 'posts:edit'));

        self::assertSame(['kind' => 'guardrail', 'names' => ['rail[4]']], $guarded->cause);
        self::assertSame([DecisionStage::BOUNDARY, DecisionStage::SESSION, DecisionStage::ALLOW, DecisionStage::ADMINISTRATION, DecisionStage::IMPLICIT], $guarded->notEvaluated);
        self::assertSame(['kind' => 'boundary', 'names' => ['cap[9]']], $bounded->cause);
        self::assertSame(['kind' => 'session', 'names' => ['credential']], $capped->cause);
        self::assertSame([DecisionStage::ALLOW, DecisionStage::ADMINISTRATION, DecisionStage::IMPLICIT], $capped->notEvaluated);
    }

    /**
     * An administration constraint that refused is named as the cause, and
     * nothing after it was evaluated but the implicit deny.
     *
     * @return void
     */
    public function testAnAdministrationRefusalIsTheCause(): void
    {
        $decision = Decision::deny(DecisionReason::ADMINISTRATION_RANK, DecisionStage::ADMINISTRATION, [], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'roles:grant'),
            new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, null, [], 'administration.rank'),
        ]);
        $explanation = Explanation::of($decision);

        self::assertSame(['kind' => 'administration', 'names' => ['administration.rank']], $explanation->cause);
        self::assertSame([DecisionStage::IMPLICIT], $explanation->notEvaluated);
    }

    /**
     * A permission held is the cause of an allow no statement decided; a denial
     * no statement and no cap decided is caused by its reason alone.
     *
     * @return void
     */
    public function testAPermissionOrAReasonIsTheCause(): void
    {
        $held = Decision::allow(DecisionStage::ALLOW, [], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('p', 0)),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:*'),
        ]);
        $failed = Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD)]);

        self::assertSame(['kind' => 'permission', 'names' => ['posts:*']], Explanation::of($held)->cause);
        self::assertSame(['kind' => 'reason', 'names' => []], Explanation::of($failed)->cause);
        self::assertSame([], Explanation::of($failed)->notEvaluated);
    }

    /**
     * An allow leaves nothing unevaluated; a denial leaves every stage after
     * the one that decided it that its trace does not reach.
     *
     * @return void
     */
    public function testTheStagesNotEvaluated(): void
    {
        $allow   = Decision::allow(DecisionStage::ALLOW);
        $tenant  = Decision::deny(DecisionReason::TENANT_SCOPE, DecisionStage::TENANT);
        $invalid = Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::BOUNDARY, [], [
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::INVALID, new StatementReference('b', 0)),
            new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED),
        ]);

        self::assertSame([], Explanation::of($allow)->notEvaluated);
        self::assertSame(\array_slice(DecisionStage::cases(), 3), Explanation::of($tenant)->notEvaluated);
        self::assertSame([DecisionStage::ALLOW, DecisionStage::ADMINISTRATION, DecisionStage::IMPLICIT], Explanation::of($invalid)->notEvaluated);
    }

    /**
     * The missing keys are each key a test found missing and could not decide
     * without, and each reference that could not be resolved, once each, in
     * order; a test that passed on a missing key names none.
     *
     * @return void
     */
    public function testTheMissingKeys(): void
    {
        $statement = new StatementReference('p', 0);
        $decision  = Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, $statement, [], null, null, [], [
                new ConditionResult('input.a', 'eq', ConditionOutcome::MISSING, false, true),
                new ConditionResult('input.b', 'eq', ConditionOutcome::HELD, true, true),
                new ConditionResult('input.c', 'eq', ConditionOutcome::UNRESOLVED, false, false, ['input.d']),
            ], ['input.e']),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, $statement, [], null, null, [], [
                new ConditionResult('input.a', 'gt', ConditionOutcome::MISSING, false, true),
            ]),
        ]);

        self::assertSame(['input.e', 'input.a', 'input.d'], Explanation::of($decision)->missingKeys());
    }

    /**
     * The schema of an explained decision is stable, version 1: every field,
     * the steps grouped by stage, the grants, the requirements and the request.
     *
     * @return void
     */
    public function testTheSchemaOfAnExplainedDecision(): void
    {
        $statement = new StatementReference('own', 0, 'key', 'Read', null);
        $user      = new Reference('user', '1');
        $decided   = new DecisionProvenance($user, $user, null, new Reference('team', 'a'), 'web');
        $request   = new ExplanationRequest('posts:read', 'posts:7', new DecisionProvenance($user, $user), $decided);
        $grant     = new GrantProvenance(GrantSource::POLICY, 'own[key]', $user, false, [], true);
        $decision  = Decision::allow(DecisionStage::ALLOW, [$statement], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, new StatementReference('own', 1, 'key')),
            new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, ['input.team' => true], null, null, ['subject.team'], [
                new ConditionResult('input.team', 'eq', ConditionOutcome::HELD),
            ]),
        ])->withEvidence(new DecisionEvidence([$grant], $request));

        self::assertSame([
            'version'    => 1,
            'effect'     => 'allow',
            'reason'     => null,
            'stage'      => 'allow',
            'decided_by' => [
                'statements' => [['policy' => 'own', 'policy_id' => 'key', 'index' => 0, 'sid' => 'Read', 'resource' => null]],
                'cause'      => null,
            ],
            'stages' => [
                ['stage' => 'deny', 'steps' => [[
                    'outcome'      => 'not_applicable',
                    'statement'    => ['policy' => 'own', 'policy_id' => 'key', 'index' => 1, 'sid' => null, 'resource' => null],
                    'cap'          => null,
                    'permission'   => null,
                    'conditions'   => [],
                    'dependencies' => [],
                    'tests'        => [],
                    'unresolved'   => [],
                ]]],
                ['stage' => 'guardrail', 'steps' => [[
                    'outcome'      => 'uncapped',
                    'statement'    => null,
                    'cap'          => null,
                    'permission'   => null,
                    'conditions'   => [],
                    'dependencies' => [],
                    'tests'        => [],
                    'unresolved'   => [],
                ]]],
                ['stage' => 'allow', 'steps' => [[
                    'outcome'      => 'matched',
                    'statement'    => ['policy' => 'own', 'policy_id' => 'key', 'index' => 0, 'sid' => 'Read', 'resource' => null],
                    'cap'          => null,
                    'permission'   => null,
                    'conditions'   => [['key' => 'input.team', 'held' => true]],
                    'dependencies' => ['subject.team'],
                    'tests'        => [['key' => 'input.team', 'operator' => 'eq', 'if_exists' => false, 'outcome' => 'held', 'missing' => false, 'unresolved' => []]],
                    'unresolved'   => [],
                ]]],
            ],
            'not_evaluated' => [],
            'grants'        => [$grant->toArray()],
            'requirements'  => [],
            'keys'          => ['input.team', 'subject.team'],
            'missing_keys'  => [],
            'request'       => $request->toArray(),
            'evidence'      => 'recorded',
        ], $decision->explain()->toArray());
    }

    /**
     * A decision made without explain mode explains with what it has, marking
     * the evidence it did not record, an assessed statement's tests included,
     * as not recorded, and the requirements by their part names and unmet parts
     * alone.
     *
     * @return void
     */
    public function testAStoredDecisionMarksWhatItDidNotRecord(): void
    {
        $requirement = new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900]), ['multifactor']);
        $decision    = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [new StatementReference('p', 0)], [$requirement], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, new StatementReference('p', 0), ['authentication' => false]),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('p', 1)),
        ]);
        $array = $decision->explain()->toArray();
        $steps = $array['stages'][0]['steps'];

        self::assertSame(Explanation::NOT_RECORDED, $array['grants']);
        self::assertSame(Explanation::NOT_RECORDED, $array['missing_keys']);
        self::assertSame(Explanation::NOT_RECORDED, $array['request']);
        self::assertSame(Explanation::NOT_RECORDED, $array['evidence']);
        self::assertSame(Explanation::NOT_RECORDED, $steps[0]['tests']);
        self::assertSame(Explanation::NOT_RECORDED, $steps[0]['unresolved']);
        self::assertSame([], $steps[1]['tests']);
        self::assertSame([['names' => ['multifactor'], 'unmet' => ['multifactor']]], $array['requirements']);
    }

    /**
     * jsonSerialize() returns the schema, so `json_encode()` renders it.
     *
     * @return void
     */
    public function testJsonSerializeReturnsTheSchema(): void
    {
        $explanation = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->explain();

        self::assertSame($explanation->toArray(), $explanation->jsonSerialize());
        self::assertSame($explanation->toArray(), \json_decode(\json_encode($explanation, \JSON_THROW_ON_ERROR), true, 512, \JSON_THROW_ON_ERROR));
    }

    /**
     * No value a check read, no operand a statement compared it with and no
     * interpolated string reaches the text or the schema of an explained check.
     *
     * @return void
     */
    public function testNoValueReachesTheExplanation(): void
    {
        $policy = Policy::fromArray(['name' => 'values', 'statements' => [[
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'resources'  => ['posts:${input.prefix}*'],
            'conditions' => ['eq' => ['input.team' => self::SECRET . '-operand', 'input.owner' => '${input.team}']],
        ]]]);
        $context = new CheckContext(['input' => ['team' => self::SECRET, 'owner' => self::SECRET, 'prefix' => self::SECRET]]);

        $context->explain();

        $explanation = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'posts:' . self::SECRET . '1', $context)->explain();
        $rendered    = $explanation->toText() . \json_encode($explanation, \JSON_THROW_ON_ERROR) . \serialize($explanation);

        self::assertNotNull($explanation->steps[3]->tests ?? null);
        self::assertStringNotContainsString(self::SECRET, $rendered);
    }
}
