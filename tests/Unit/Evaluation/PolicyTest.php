<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for the policy value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Policy::class)]
final class PolicyTest extends TestCase
{
    /**
     * Policy round-trips through fromArray / toArray and defaults to version 1.
     *
     * @return void
     */
    public function testRoundTripsAndDefaultsVersion(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'example',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        self::assertSame('example', $policy->name);
        self::assertCount(1, $policy->statements);
        self::assertContainsOnlyInstancesOf(Statement::class, $policy->statements);
        self::assertSame(Policy::CURRENT_VERSION, $policy->version);

        $array = $policy->toArray();
        self::assertSame(1, $array['version']);
        self::assertSame('example', $array['name']);
    }

    /**
     * Accepts an explicit version.
     *
     * @return void
     */
    public function testAcceptsExplicitVersion(): void
    {
        $policy = Policy::fromArray([
            'version'    => 2,
            'name'       => 'x',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        self::assertSame(2, $policy->version);
    }

    /**
     * Rejects missing name.
     *
     * @return void
     */
    public function testRejectsMissingName(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Policy::fromArray(['statements' => []]);
    }

    /**
     * Rejects empty name.
     *
     * @return void
     */
    public function testRejectsEmptyName(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Policy::fromArray(['name' => '', 'statements' => []]);
    }

    /**
     * Rejects missing statements.
     *
     * @return void
     */
    public function testRejectsMissingStatements(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Policy::fromArray(['name' => 'example']);
    }

    /**
     * Rejects non-integer or non-positive version.
     *
     * @return void
     */
    public function testRejectsInvalidVersion(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Policy::fromArray([
            'version'    => 0,
            'name'       => 'x',
            'statements' => [],
        ]);
    }

    /**
     * Rejects non-array statements.
     *
     * @return void
     */
    public function testRejectsStatementsNotArrays(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line argument.type (test passes deliberately-invalid input to exercise validation error path)
        Policy::fromArray(['name' => 'x', 'statements' => ['not-an-array']]);
    }

    /**
     * Non-integer version is rejected.
     *
     * @return void
     */
    public function testRejectsNonIntegerVersion(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line argument.type (test passes deliberately-invalid input to exercise validation error path)
        Policy::fromArray([
            'version'    => '1',
            'name'       => 'x',
            'statements' => [],
        ]);
    }

    /**
     * toArray emits version, name and statements in canonical order
     * (kills the version-key literal mutants).
     *
     * @return void
     */
    public function testToArrayShape(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'sample',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        self::assertSame([
            'version'    => 1,
            'name'       => 'sample',
            'statements' => [
                [
                    'effect'    => 'allow',
                    'actions'   => ['x'],
                    'resources' => ['*'],
                ],
            ],
        ], $policy->toArray());
    }

    /**
     * Empty name string is rejected.
     *
     * @return void
     */
    public function testRejectsNonStringName(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line argument.type (test passes deliberately-invalid input to exercise validation error path)
        Policy::fromArray(['name' => 42, 'statements' => []]);
    }

    /**
     * Lock the v1 document shape. The fixture exercises every
     * slot — effect, actions, resources, and a condition map
     * with multiple operators — and round-trips it through
     * `fromArray` / `toArray`. If a future schema change alters
     * the canonical layout without bumping `Policy::CURRENT_VERSION`,
     * this test fails loudly and forces the change to land
     * deliberately.
     *
     * @return void
     */
    public function testVersion1DocumentShapeIsLocked(): void
    {
        $document = [
            'version'    => 1,
            'name'       => 'v1-fixture',
            'statements' => [
                [
                    'effect'     => 'allow',
                    'actions'    => ['posts:create', 'posts:update'],
                    'resources'  => ['arn:posts:*'],
                    'conditions' => [
                        'tenant' => ['eq' => 'org-1'],
                        'ip'     => ['cidr' => '10.0.0.0/8'],
                    ],
                ],
                [
                    'effect'    => 'deny',
                    'actions'   => ['posts:delete'],
                    'resources' => ['arn:posts:42'],
                ],
            ],
        ];

        $policy   = Policy::fromArray($document);
        $rendered = $policy->toArray();

        self::assertSame(1, $policy->version);
        self::assertSame(Policy::CURRENT_VERSION, $policy->version);
        self::assertSame($document, $rendered);
    }

    /**
     * An explicit future `version` is preserved on the round
     * trip. This pins the forward-compatibility contract: even if
     * the current engine would evaluate a v2 document identically
     * to v1, the persisted version number must flow through
     * untouched so downstream tooling can detect the bump.
     *
     * @return void
     */
    public function testFutureVersionIsPreservedThroughRoundTrip(): void
    {
        $policy = Policy::fromArray([
            'version'    => 2,
            'name'       => 'forward-compat',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        self::assertSame(2, $policy->version);
        self::assertSame(2, $policy->toArray()['version']);
    }
}
