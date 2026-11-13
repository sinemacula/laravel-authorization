<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;

/**
 * Unit tests for the decision value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Decision::class)]
final class DecisionTest extends TestCase
{
    /**
     * allow() returns an allow with no reason, decided at the stage, and
     * defaults to no statements and an empty trace.
     *
     * @return void
     */
    public function testAllowDefaultsStatementsAndTrace(): void
    {
        $decision = Decision::allow(DecisionStage::ALLOW);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * allow() keeps the supplied statements and trace untouched.
     *
     * @return void
     */
    public function testAllowKeepsStatementsAndTrace(): void
    {
        $statements = [new StatementReference('p', 0)];
        $trace      = [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statements[0])];
        $decision   = Decision::allow(DecisionStage::ALLOW, $statements, $trace);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame($trace, $decision->trace);
    }

    /**
     * deny() returns a denial for the reason, decided at the stage, and
     * defaults to no statements and an empty trace.
     *
     * @return void
     */
    public function testDenyDefaultsStatementsAndTrace(): void
    {
        $decision = Decision::deny(DecisionReason::SUBJECT_INACTIVE, DecisionStage::SUBJECT);

        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * deny() keeps the supplied statements and trace untouched.
     *
     * @return void
     */
    public function testDenyKeepsStatementsAndTrace(): void
    {
        $statements = [new StatementReference('p', 1), new StatementReference('q', 0)];
        $trace      = [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, $statements[0]),
            new TraceEntry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, $statements[1]),
        ];
        $decision = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $statements, $trace);

        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame($trace, $decision->trace);
    }

    /**
     * isAllowed() is true for an allow and false for a denial.
     *
     * @return void
     */
    public function testIsAllowed(): void
    {
        self::assertTrue(Decision::allow(DecisionStage::ALLOW)->isAllowed());
        self::assertFalse(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->isAllowed());
    }

    /**
     * withStep() returns the decision with the entry appended to its trace,
     * keeping its effect, reason, stage and statements, and leaves the original
     * decision as it was.
     *
     * @return void
     */
    public function testWithStepAppendsToTheTrace(): void
    {
        $statements = [new StatementReference('p', 0)];
        $first      = new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, $statements[0]);
        $second     = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD);
        $original   = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $statements, [$first]);

        $decision = $original->withStep($second);

        self::assertNotSame($original, $decision);
        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame([$first, $second], $decision->trace);
        self::assertSame([$first], $original->trace);
    }

    /**
     * withStep() keeps an allow an allow, with no reason.
     *
     * @return void
     */
    public function testWithStepKeepsAnAllow(): void
    {
        $entry    = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD);
        $decision = Decision::allow(DecisionStage::ALLOW)->withStep($entry);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([$entry], $decision->trace);
    }

    /**
     * explain() renders an allow with the stage and every statement that
     * decided it, separated by commas.
     *
     * @return void
     */
    public function testExplainAllowWithStatements(): void
    {
        $decision = Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0), new StatementReference('q', 1)]);

        self::assertSame("ALLOW at the allow stage by p#0, q#1.\n  evidence: not recorded (explain mode off)", $decision->explain()->toText());
    }

    /**
     * explain() renders an allow with no statements, such as a permission held,
     * without naming any.
     *
     * @return void
     */
    public function testExplainAllowWithoutStatements(): void
    {
        self::assertSame("ALLOW at the allow stage.\n  evidence: not recorded (explain mode off)", Decision::allow(DecisionStage::ALLOW)->explain()->toText());
    }

    /**
     * explain() renders a denial with no statements as its reason code and
     * label, then the stage.
     *
     * @return void
     */
    public function testExplainDenyWithoutStatements(): void
    {
        self::assertSame(
            "DENY (no_match: no statement or permission names it) at the implicit stage.\n  evidence: not recorded (explain mode off)",
            Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->explain()->toText(),
        );
    }

    /**
     * explain() renders a denial with the statements that decided it.
     *
     * @return void
     */
    public function testExplainDenyWithStatements(): void
    {
        $decision = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [new StatementReference('p', 2)]);

        self::assertSame(
            "DENY (explicit_deny: an applicable statement denies it) at the deny stage by p#2.\n"
            . "  not evaluated: guardrail, boundary, session, allow, administration, implicit\n  evidence: not recorded (explain mode off)",
            $decision->explain()->toText(),
        );
    }

    /**
     * explain() renders every reason with its code and label.
     *
     * @return void
     */
    public function testExplainCoversEveryReason(): void
    {
        foreach (DecisionReason::cases() as $reason) {
            self::assertSame(
                "DENY ({$reason->value}: {$reason->label()}) at the implicit stage.\n  evidence: not recorded (explain mode off)",
                Decision::deny($reason, DecisionStage::IMPLICIT)->explain()->toText(),
            );
        }
    }

    /**
     * explain() follows the first line with one indented line for each trace
     * entry, in order.
     *
     * @return void
     */
    public function testExplainIncludesTraceLines(): void
    {
        $p0       = new StatementReference('p', 0);
        $p1       = new StatementReference('p', 1);
        $decision = Decision::allow(DecisionStage::ALLOW, [$p1], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, $p0),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $p1, ['owner' => true]),
        ]);

        self::assertSame(
            "ALLOW at the allow stage by p#1.\n"
            . "  [deny] p#0: not_applicable\n"
            . "  [allow] p#1: matched (owner held)\n  evidence: not recorded (explain mode off)",
            $decision->explain()->toText(),
        );
    }

    /**
     * explain() renders a permission step appended by withStep() as the last
     * trace line.
     *
     * @return void
     */
    public function testExplainIncludesPermissionStep(): void
    {
        $decision = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('p', 0)),
        ])->withStep(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD));

        self::assertSame(
            "DENY (no_match: no statement or permission names it) at the implicit stage.\n"
            . "  [allow] p#0: not_applicable\n"
            . "  [allow] permission: not_held\n  evidence: not recorded (explain mode off)",
            $decision->explain()->toText(),
        );
    }

    /**
     * insufficientAuthentication() returns an insufficient_authentication
     * denial at the stage, by the statements, with each requirement and its
     * unmet parts, and no freshness.
     *
     * @return void
     */
    public function testInsufficientAuthentication(): void
    {
        $statements   = [new StatementReference('p', 0), new StatementReference('p', 2)];
        $requirements = self::requirements();
        $trace        = [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, $statements[0], ['authentication' => false])];
        $decision     = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, $statements, $requirements, $trace);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame($requirements, $decision->requirements);
        self::assertSame($trace, $decision->trace);
        self::assertNull($decision->freshness);
        self::assertSame([], Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [], [])->trace);
    }

    /**
     * Allows and plain denials carry no requirements and no freshness.
     *
     * @return void
     */
    public function testOtherDecisionsCarryNoRequirements(): void
    {
        self::assertSame([], Decision::allow(DecisionStage::ALLOW)->requirements);
        self::assertSame([], Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->requirements);
        self::assertNull(Decision::allow(DecisionStage::ALLOW)->freshness);
    }

    /**
     * withFreshness() keeps everything else and adds the freshness, and gives
     * the decision itself back for none.
     *
     * @return void
     */
    public function testWithFreshness(): void
    {
        $decision  = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [new StatementReference('p', 0)], self::requirements());
        $freshness = new RequirementFreshness('session-1');
        $fresh     = $decision->withFreshness($freshness);

        self::assertSame($decision, $decision->withFreshness(null));
        self::assertSame($freshness, $fresh->freshness);
        self::assertSame($decision->reason, $fresh->reason);
        self::assertSame($decision->stage, $fresh->stage);
        self::assertSame($decision->statements, $fresh->statements);
        self::assertSame($decision->requirements, $fresh->requirements);
        self::assertSame($decision->trace, $fresh->trace);
    }

    /**
     * withStep() keeps the reason, the requirements and the freshness.
     *
     * @return void
     */
    public function testStepsKeepRequirementsAndFreshness(): void
    {
        $freshness = new RequirementFreshness('session-1');
        $decision  = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [], self::requirements())->withFreshness($freshness);

        $stepped = $decision->withStep(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD));

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $stepped->reason);
        self::assertSame($decision->requirements, $stepped->requirements);
        self::assertSame($freshness, $stepped->freshness);
    }

    /**
     * A decision reads no requirement until withFreshness() names what it read,
     * which withStep() and withEvidence() keep, and withFreshness() for no
     * freshness gives the decision itself back, naming none.
     *
     * @return void
     */
    public function testTheRequirementsReadAreKeptAcrossTheDecision(): void
    {
        $decision = Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0)]);
        $read     = $decision->withFreshness(new RequirementFreshness('session-1'), ['multifactor', 'phishing_resistant']);

        self::assertSame([], $decision->requirementsRead);
        self::assertSame([], Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->requirementsRead);
        self::assertSame([], Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [], self::requirements())->requirementsRead);
        self::assertSame([], $decision->withFreshness(new RequirementFreshness('session-1'))->requirementsRead);
        self::assertSame($decision, $decision->withFreshness(null, ['multifactor']));
        self::assertSame(['multifactor', 'phishing_resistant'], $read->requirementsRead);
        self::assertSame(['multifactor', 'phishing_resistant'], $read->withStep(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD))->requirementsRead);
        self::assertSame(['multifactor', 'phishing_resistant'], $read->withEvidence(new DecisionEvidence([]))->requirementsRead);
    }

    /**
     * withFreshness() adds to what the decision already read: it names every
     * requirement either read, once each, sorted, and is reused no longer than
     * the earlier instant either stops being met; adding no freshness keeps the
     * decision's own.
     *
     * @return void
     */
    public function testWithFreshnessAddsToWhatTheDecisionRead(): void
    {
        $one     = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 13:00:00'));
        $noon    = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $later   = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 14:00:00'));
        $read    = Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0)])->withFreshness($one, ['phishing_resistant', 'multifactor', 'phishing_resistant']);
        $added   = $read->withFreshness($noon, ['multifactor', 'biometric']);
        $kept    = $read->withFreshness(null);
        $outlast = $read->withFreshness($later, ['multifactor']);

        self::assertSame(['multifactor', 'phishing_resistant'], $read->requirementsRead);
        self::assertSame(['biometric', 'multifactor', 'phishing_resistant'], $added->requirementsRead);
        self::assertSame($noon, $added->freshness);
        self::assertSame($read->statements, $added->statements);
        self::assertSame($one, $kept->freshness);
        self::assertSame(['multifactor', 'phishing_resistant'], $kept->requirementsRead);
        self::assertSame($one, $outlast->freshness);
        self::assertSame(['multifactor', 'phishing_resistant'], $outlast->requirementsRead);
    }

    /**
     * isFreshFor() always holds for a decision that read no requirement, and
     * otherwise asks its freshness.
     *
     * @return void
     */
    public function testIsFreshFor(): void
    {
        $until    = new \DateTimeImmutable('2026-11-06 12:00:00');
        $before   = new \DateTimeImmutable('2026-11-06 11:00:00');
        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness('session-1', $until));

        self::assertTrue(Decision::allow(DecisionStage::ALLOW)->isFreshFor(null));
        self::assertTrue(Decision::allow(DecisionStage::ALLOW)->isFreshFor('any'));
        self::assertTrue($decision->isFreshFor('session-1', $before));
        self::assertFalse($decision->isFreshFor('session-2', $before));
        self::assertFalse($decision->isFreshFor('session-1', $until));
    }

    /**
     * explain() renders each requirement an insufficient authentication names,
     * with its unmet parts, after the verdict.
     *
     * @return void
     */
    public function testExplainInsufficientAuthentication(): void
    {
        $decision = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [new StatementReference('p', 0), new StatementReference('p', 1)], self::requirements());

        self::assertSame(
            "DENY (insufficient_authentication: a statement allows it once further authentication is met) at the implicit stage by p#0, p#1.\n"
            . "  requirement multifactor, phishing_resistant: unmet multifactor\n"
            . "  requirement assurance_level: unmet assurance_level\n  evidence: not recorded (explain mode off)",
            $decision->explain()->toText(),
        );
    }

    /**
     * The keys are every condition key the trace tested, each once, in the
     * order first tested, held or failed alike; a decision whose trace tested
     * none depended on none.
     *
     * @return void
     */
    public function testKeysAreEveryConditionKeyTheTraceTestedOnce(): void
    {
        $statement = new StatementReference('p', 0);
        $decision  = Decision::allow(DecisionStage::ALLOW, [], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, $statement, ['resource.status' => false, 'input.flag' => true]),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, ['input.flag' => true, 'resource.tier' => false, 'subject.department' => true]),
        ]);

        self::assertSame(['resource.status', 'input.flag', 'resource.tier', 'subject.department'], $decision->keys());
        self::assertSame([], Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->keys());
    }

    /**
     * A decision carries no evidence until it is given some; withEvidence()
     * adds it and keeps everything else, and withStep() and withFreshness()
     * keep it.
     *
     * @return void
     */
    public function testEvidenceIsKeptAcrossTheDecision(): void
    {
        $decision  = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [new StatementReference('p', 0)], self::requirements());
        $evidence  = new DecisionEvidence([GrantProvenance::unavailable('posts:read')]);
        $explained = $decision->withEvidence($evidence);
        $freshness = new RequirementFreshness('session-1');

        self::assertFalse($decision->hasEvidence());
        self::assertNull($decision->evidence);
        self::assertTrue($explained->hasEvidence());
        self::assertSame($evidence, $explained->evidence);
        self::assertSame($decision->reason, $explained->reason);
        self::assertSame($decision->stage, $explained->stage);
        self::assertSame($decision->statements, $explained->statements);
        self::assertSame($decision->requirements, $explained->requirements);
        self::assertSame($decision->trace, $explained->trace);
        self::assertSame($evidence, $explained->withStep(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD))->evidence);
        self::assertSame($evidence, $explained->withFreshness($freshness)->evidence);
        self::assertSame($freshness, $explained->withFreshness($freshness)->freshness);
    }

    /**
     * A decision names no activation until it is given some; withActivations()
     * keeps each once, sorted, and everything else, an empty list changing
     * nothing; withStep(), withFreshness() and withEvidence() keep them.
     *
     * @return void
     */
    public function testActivationsAreKeptAcrossTheDecision(): void
    {
        $step      = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:read');
        $evidence  = new DecisionEvidence([GrantProvenance::unavailable('posts:read')]);
        $freshness = new RequirementFreshness('session-1');
        $decision  = Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0)], [$step])->withFreshness($freshness, ['multifactor'])->withEvidence($evidence);
        $named     = $decision->withActivations(['b', 'a', 'b']);

        self::assertSame([], $decision->activations);
        self::assertSame($decision, $decision->withActivations([]));
        self::assertSame(['a', 'b'], $named->activations);
        self::assertSame(['b'], $named->withActivations(['b'])->activations);
        self::assertSame($decision->effect, $named->effect);
        self::assertSame($decision->reason, $named->reason);
        self::assertSame($decision->stage, $named->stage);
        self::assertSame($decision->statements, $named->statements);
        self::assertSame($decision->trace, $named->trace);
        self::assertSame($decision->requirements, $named->requirements);
        self::assertSame($freshness, $named->freshness);
        self::assertSame($evidence, $named->evidence);
        self::assertSame(['multifactor'], $named->requirementsRead);
        self::assertSame(['a', 'b'], $named->withStep(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED))->activations);
        self::assertSame(['a', 'b'], $named->withFreshness(new RequirementFreshness('session-1'))->activations);
        self::assertSame(['a', 'b'], $named->withEvidence(new DecisionEvidence)->activations);
    }

    /**
     * The keys also hold every `${…}` reference a statement it assessed names,
     * after the condition keys of its step, each once.
     *
     * @return void
     */
    public function testKeysHoldTheInterpolationDependencies(): void
    {
        $statement = new StatementReference('p', 0);
        $decision  = Decision::allow(DecisionStage::ALLOW, [], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, $statement, ['input.a' => false], null, null, ['subject.id', 'input.a']),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, ['input.b' => true], null, null, ['subject.id', 'request.ip']),
        ]);

        self::assertSame(['input.a', 'subject.id', 'input.b', 'request.ip'], $decision->keys());
    }

    /**
     * explain() returns the explanation of the decision, a projection of it.
     *
     * @return void
     */
    public function testExplainReturnsTheExplanation(): void
    {
        $decision = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [new StatementReference('p', 0)]);

        self::assertEquals(Explanation::of($decision), $decision->explain());
    }

    /**
     * Return two candidate requirements.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>
     */
    private static function requirements(): array
    {
        return [
            new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]), ['multifactor']),
            new UnmetRequirement(new AuthenticationRequirement(['assurance_level' => null], 'aal2'), ['assurance_level']),
        ];
    }
}
