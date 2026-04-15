<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for the policy statement value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Statement::class)]
#[CoversClass(ConditionEvaluator::class)]
final class StatementTest extends TestCase
{
    /**
     * Round-trip a minimal statement through fromArray/toArray.
     *
     * @return void
     */
    public function testRoundTripsThroughArray(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:create'],
            'resources'  => ['arn:posts:1'],
            'conditions' => ['tenant' => ['eq' => 'org-1']],
        ]);

        self::assertSame(PolicyEffect::ALLOW, $statement->effect);
        self::assertSame(['posts:create'], $statement->actions);
        self::assertSame(['arn:posts:1'], $statement->resources);
        self::assertSame(['tenant' => ['eq' => 'org-1']], $statement->conditions);

        $array = $statement->toArray();
        self::assertSame('allow', $array['effect']);
        self::assertSame(['posts:create'], $array['actions']);
    }

    /**
     * Defaults when resources / conditions are omitted.
     *
     * @return void
     */
    public function testDefaultsResourcesToWildcardAndOmitsEmptyConditions(): void
    {
        $statement = Statement::fromArray([
            'effect'  => 'deny',
            'actions' => ['posts:delete'],
        ]);

        self::assertSame(['*'], $statement->resources);
        self::assertSame([], $statement->conditions);
        self::assertArrayNotHasKey('conditions', $statement->toArray());
    }

    /**
     * Reject a missing effect.
     *
     * @return void
     */
    public function testRejectsMissingEffect(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Statement::fromArray(['actions' => ['x']]);
    }

    /**
     * Reject an invalid effect.
     *
     * @return void
     */
    public function testRejectsInvalidEffect(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'audit', 'actions' => ['x']]);
    }

    /**
     * Reject missing actions.
     *
     * @return void
     */
    public function testRejectsMissingActions(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'allow']);
    }

    /**
     * Reject empty actions.
     *
     * @return void
     */
    public function testRejectsEmptyActions(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'allow', 'actions' => []]);
    }

    /**
     * Reject non-string actions.
     *
     * @return void
     */
    public function testRejectsNonStringActions(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Statement::fromArray(['effect' => 'allow', 'actions' => [123]]);
    }

    /**
     * Reject non-array resources.
     *
     * @return void
     */
    public function testRejectsNonArrayResources(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'resources' => 'nope']);
    }

    /**
     * Empty resources collapse to wildcard.
     *
     * @return void
     */
    public function testEmptyResourcesCollapseToWildcard(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:create'],
            'resources' => [],
        ]);

        self::assertSame(['*'], $statement->resources);
    }

    /**
     * Reject non-string resources.
     *
     * @return void
     */
    public function testRejectsNonStringResources(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'resources' => [42]]);
    }

    /**
     * Reject non-array conditions.
     *
     * @return void
     */
    public function testRejectsNonArrayConditions(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => 'nope']);
    }

    /**
     * Reject non-string condition keys.
     *
     * @return void
     */
    public function testRejectsNonStringConditionKeys(): void
    {
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => [42 => 'v']]);
    }

    /**
     * Wildcard action matching.
     *
     * @return void
     */
    public function testMatchesWildcardActions(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:*']]);

        self::assertTrue($statement->matches('posts:create'));
        self::assertTrue($statement->matches('posts:delete'));
        self::assertFalse($statement->matches('users:create'));
    }

    /**
     * Wildcard resource matching.
     *
     * @return void
     */
    public function testMatchesWildcardResources(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:*'],
        ]);

        self::assertTrue($statement->matches('posts:read', 'arn:posts:1'));
        self::assertTrue($statement->matches('posts:read', 'arn:posts:99'));
        self::assertFalse($statement->matches('posts:read', 'arn:users:1'));
    }

    /**
     * Resource-less match short-circuits to action match.
     *
     * @return void
     */
    public function testResourcelessMatchSkipsResourceCheck(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:1'],
        ]);

        self::assertTrue($statement->matches('posts:read'));
    }

    /**
     * Missing context key fails condition without throwing.
     *
     * @return void
     */
    public function testMissingContextKeyFailsCondition(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => ['eq' => 'org-1']],
        ]);

        self::assertFalse($statement->evaluateConditions([]));
    }

    /**
     * Scalar condition compared by identity.
     *
     * @return void
     */
    public function testScalarConditionComparedByIdentity(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => 'org-1'],
        ]);

        self::assertTrue($statement->evaluateConditions(['tenant' => 'org-1']));
        self::assertFalse($statement->evaluateConditions(['tenant' => 'org-2']));
    }

    /**
     * Unknown operators short-circuit to false.
     *
     * @return void
     */
    public function testUnknownOperatorFailsClosed(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => ['unknown_op' => 'org-1']],
        ]);

        self::assertFalse($statement->evaluateConditions(['tenant' => 'org-1']));
    }

    /**
     * Data provider for operators.
     *
     * @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function operatorProvider(): array
    {
        return [
            'eq-true'          => [['tenant' => ['eq' => 'org-1']],              ['tenant' => 'org-1'],          true],
            'eq-false'         => [['tenant' => ['eq' => 'org-1']],              ['tenant' => 'org-2'],          false],
            'neq-true'         => [['tenant' => ['neq' => 'org-1']],             ['tenant' => 'org-2'],          true],
            'neq-false'        => [['tenant' => ['neq' => 'org-1']],             ['tenant' => 'org-1'],          false],
            'in-true'          => [['role' => ['in' => ['admin', 'staff']]],     ['role' => 'admin'],            true],
            'in-false'         => [['role' => ['in' => ['admin', 'staff']]],     ['role' => 'guest'],            false],
            'in-non-array'     => [['role' => ['in' => 'admin']],                ['role' => 'admin'],            false],
            'not_in-true'      => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'guest'],            true],
            'not_in-false'     => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'admin'],            false],
            'starts_with-true' => [['email' => ['starts_with' => 'admin@']],     ['email' => 'admin@example'],   true],
            'ends_with-true'   => [['email' => ['ends_with' => 'sine.co']],      ['email' => 'a@sine.co'],       true],
            'cidr-match'       => [['ip' => ['cidr' => '192.168.1.0/24']],       ['ip' => '192.168.1.25'],       true],
            'cidr-no-match'    => [['ip' => ['cidr' => '192.168.1.0/24']],       ['ip' => '10.0.0.1'],           false],
            'cidr-exact'       => [['ip' => ['cidr' => '192.168.1.1']],          ['ip' => '192.168.1.1'],        true],
            'cidr-zero-bits'   => [['ip' => ['cidr' => '0.0.0.0/0']],            ['ip' => '1.2.3.4'],            true],
            'cidr-mask-32-match' => [['ip' => ['cidr' => '192.168.1.1/32']],     ['ip' => '192.168.1.1'],        true],
            'cidr-mask-32-miss' => [['ip' => ['cidr' => '192.168.1.1/32']],      ['ip' => '192.168.1.2'],        false],
            'cidr-mask-31-match' => [['ip' => ['cidr' => '192.168.1.0/31']],     ['ip' => '192.168.1.1'],        true],
            'cidr-mask-31-miss' => [['ip' => ['cidr' => '192.168.1.0/31']],      ['ip' => '192.168.1.2'],        false],
            'between-equal-lower' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-15'], true],
            'between-equal-upper' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-20'], true],
            'between-just-below' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-14'], false],
            'between-just-above' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-21'], false],
            'before-equal'      => [['at' => ['before' => '2026-04-15']],         ['at' => '2026-04-15'],         false],
            'after-equal'       => [['at' => ['after' => '2026-04-15']],          ['at' => '2026-04-15'],         false],
            'cidr-bad-ip'      => [['ip' => ['cidr' => '192.168.1.0/24']],       ['ip' => 'not-an-ip'],          false],
            'cidr-bad-bits'    => [['ip' => ['cidr' => '192.168.1.0/abc']],      ['ip' => '192.168.1.25'],       false],
            'cidr-bits-too-big' => [['ip' => ['cidr' => '192.168.1.0/64']],      ['ip' => '192.168.1.25'],       false],
            'before-iso'       => [['at' => ['before' => '2026-04-15']],         ['at' => '2026-04-14'],         true],
            'before-iso-false' => [['at' => ['before' => '2026-04-15']],         ['at' => '2026-04-16'],         false],
            'after-iso'        => [['at' => ['after' => '2026-04-15']],          ['at' => '2026-04-16'],         true],
            'between-iso'      => [['at' => ['between' => ['2026-04-10', '2026-04-20']]], ['at' => '2026-04-15'], true],
            'between-outside'  => [['at' => ['between' => ['2026-04-10', '2026-04-12']]], ['at' => '2026-04-15'], false],
            'between-bad-shape' => [['at' => ['between' => ['2026-04-10']]],     ['at' => '2026-04-15'],         false],
            'between-bad-left' => [['at' => ['between' => ['bad', '2026-04-20']]], ['at' => '2026-04-15'],       false],
            'time-invalid'     => [['at' => ['before' => 'not-a-date']],         ['at' => '2026-04-14'],         false],
            'time-int'         => [['at' => ['before' => 2_000_000_000]],        ['at' => 1_000_000_000],        true],
            'time-empty-string' => [['at' => ['before' => '2026-04-15']],        ['at' => ''],                   false],
        ];
    }

    /**
     * Exercise every supported operator.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $context
     * @param  bool                  $expected
     * @return void
     */
    #[DataProvider('operatorProvider')]
    public function testOperatorMatrix(array $conditions, array $context, bool $expected): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => $conditions,
        ]);

        self::assertSame($expected, $statement->evaluateConditions($context));
    }

    /**
     * Resources-not-match short-circuit.
     *
     * @return void
     */
    public function testResourceMatchFailsWhenPatternDoesNotMatch(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:*'],
            'resources' => ['arn:posts:1'],
        ]);

        self::assertFalse($statement->matches('posts:create', 'arn:users:1'));
    }
}
