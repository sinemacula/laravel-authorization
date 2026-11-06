<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\StatementEntries;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;

/**
 * Unit tests for `StatementEntries`, which gathers the statements of a
 * decision's policies and boundaries in a fixed order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(StatementEntries::class)]
final class StatementEntriesTest extends TestCase
{
    /**
     * Nothing to gather gives nothing.
     *
     * @return void
     */
    public function testGathersNothingFromNoPolicies(): void
    {
        self::assertSame(['deny' => [], 'allow' => [], 'boundaries' => []], (new StatementEntries)->of([]));
    }

    /**
     * The policies' statements come out deny and allow apart, the policies by
     * name and each statement by its position, each with its reference and the
     * trace entry of its stage, whatever order the policies were given in.
     *
     * @return void
     */
    public function testOrdersThePoliciesByNameAndTheStatementsByPosition(): void
    {
        $b = self::policy('b', [['effect' => 'allow', 'actions' => ['x']], ['effect' => 'deny', 'actions' => ['x']]]);
        $a = self::policy('a', [['effect' => 'deny', 'actions' => ['x']], ['effect' => 'allow', 'actions' => ['x']], ['effect' => 'allow', 'actions' => ['y']]]);

        $gathered = (new StatementEntries)->of([$b, $a]);

        self::assertSame(['a#0', 'b#1'], self::labels($gathered['deny']));
        self::assertSame(['a#1', 'a#2', 'b#0'], self::labels($gathered['allow']));
        self::assertSame([], $gathered['boundaries']);
        self::assertSame($a->statements[0], $gathered['deny'][0][1]);
        self::assertEquals(new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, new StatementReference('a', 0)), $gathered['deny'][0][2]);
        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('b', 0)), $gathered['allow'][2][2]);
        self::assertEquals((new StatementEntries)->of([$a, $b]), $gathered);
    }

    /**
     * Policies of one name are ordered by stored key, then attached resource,
     * then document.
     *
     * @return void
     */
    public function testOrdersPoliciesOfOneNameByKeyResourceAndDocument(): void
    {
        $second = self::policy('p', [['effect' => 'allow', 'actions' => ['x']]])->withId('2');
        $first  = self::policy('p', [['effect' => 'allow', 'actions' => ['y']]])->withId('1');
        $typed  = self::policy('p', [['effect' => 'allow', 'actions' => ['z'], 'principals' => ['user:1']]])->withId('1')->withResource('posts:*');
        $later  = self::policy('q', [['effect' => 'allow', 'actions' => ['b']]]);
        $sooner = self::policy('q', [['effect' => 'allow', 'actions' => ['a']]]);

        $gathered = (new StatementEntries)->of([$later, $typed, $second, $sooner, $first]);

        $expected = [$first->statements[0], $typed->statements[0], $second->statements[0], $sooner->statements[0], $later->statements[0]];

        self::assertSame($expected, \array_column($gathered['allow'], 1));
    }

    /**
     * A boundary's deny statements join the deny stage after every policy's,
     * and its allow statements are kept apart, one list per boundary, each with
     * the boundary stage's trace entry, the boundaries by name.
     *
     * @return void
     */
    public function testKeepsEachBoundarysAllowsApartAndJoinsItsDenies(): void
    {
        $policy = self::policy('z', [['effect' => 'deny', 'actions' => ['x']], ['effect' => 'allow', 'actions' => ['x']]]);
        $second = self::policy('b-cap', [['effect' => 'allow', 'actions' => ['x']]]);
        $first  = self::policy('a-cap', [['effect' => 'deny', 'actions' => ['y']], ['effect' => 'allow', 'actions' => ['x']], ['effect' => 'allow', 'actions' => ['z']]]);

        $gathered = (new StatementEntries)->of([$policy], [$second, $first]);

        self::assertSame(['z#0', 'a-cap#0'], self::labels($gathered['deny']));
        self::assertSame(['z#1'], self::labels($gathered['allow']));
        self::assertCount(2, $gathered['boundaries']);
        self::assertSame(['a-cap#1', 'a-cap#2'], self::labels($gathered['boundaries'][0]));
        self::assertSame(['b-cap#0'], self::labels($gathered['boundaries'][1]));
        self::assertEquals(new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::NOT_APPLICABLE, new StatementReference('a-cap', 1)), $gathered['boundaries'][0][0][2]);
        self::assertEquals(new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, new StatementReference('a-cap', 0)), $gathered['deny'][1][2]);
    }

    /**
     * What a policy gives is worked out once while the policy lives: asked
     * again, it hands back the same references and trace entries, as a policy
     * and as a boundary alike.
     *
     * @return void
     */
    public function testWorksOutEachPolicyOnce(): void
    {
        $entries  = new StatementEntries;
        $policy   = self::policy('p', [['effect' => 'deny', 'actions' => ['x']], ['effect' => 'allow', 'actions' => ['x']]]);
        $boundary = self::policy('cap', [['effect' => 'allow', 'actions' => ['x']]]);

        $first  = $entries->of([$policy], [$boundary]);
        $second = $entries->of([$policy], [$boundary]);

        self::assertSame($first['deny'][0][0], $second['deny'][0][0]);
        self::assertSame($first['deny'][0][2], $second['deny'][0][2]);
        self::assertSame($first['allow'][0][2], $second['allow'][0][2]);
        self::assertSame($first['boundaries'][0][0][2], $second['boundaries'][0][0][2]);
        self::assertNotSame($first['allow'][0][2], (new StatementEntries)->of([$policy])['allow'][0][2]);
    }

    /**
     * Build a policy of the statement documents.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::fromArray(['name' => $name, 'statements' => $statements]);
    }

    /**
     * Return each entry's statement as its policy name and position.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Evaluation\StatementReference, 1: mixed, 2: mixed}>  $entries
     * @return list<string>
     */
    private static function labels(array $entries): array
    {
        return \array_map(static fn (array $entry): string => $entry[0]->policy . '#' . $entry[0]->index, $entries);
    }
}
