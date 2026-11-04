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
     * Accepts an explicit version 1, the only version this package knows.
     *
     * @return void
     */
    public function testAcceptsExplicitVersion(): void
    {
        $policy = Policy::fromArray([
            'version'    => 1,
            'name'       => 'x',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        self::assertSame(1, $policy->version);
        self::assertSame(1, $policy->toArray()['version']);
    }

    /**
     * A null version is treated as absent and defaults to the current version.
     *
     * @return void
     */
    public function testNullVersionDefaultsToCurrentVersion(): void
    {
        $policy = Policy::fromArray([
            'version'    => null,
            'name'       => 'x',
            'statements' => [],
        ]);

        self::assertSame(Policy::CURRENT_VERSION, $policy->version);
    }

    /**
     * An unknown top-level key is refused, naming the offending key.
     *
     * @return void
     */
    public function testRejectsUnknownTopLevelKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document has unknown keys: description.');

        Policy::fromArray([
            'name'        => 'x',
            'description' => 'not part of the schema',
            'statements'  => [],
        ]);
    }

    /**
     * Several unknown keys are all named, in document order and separated by a
     * comma, including a key that differs from a known key only by case.
     *
     * @return void
     */
    public function testRejectsSeveralUnknownTopLevelKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document has unknown keys: Statements, extra.');

        Policy::fromArray([
            'name'       => 'x',
            'Statements' => [],
            'statements' => [],
            'extra'      => true,
        ]);
    }

    /**
     * An integer top-level key is refused as unknown.
     *
     * @return void
     */
    public function testRejectsIntegerTopLevelKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document has unknown keys: 0.');

        // @phpstan-ignore-next-line argument.type
        Policy::fromArray(['name' => 'x', 'statements' => [], 0 => 'stray']);
    }

    /**
     * Unknown keys are refused before any other validation runs, so a document
     * with an unknown key and no name reports the unknown key.
     *
     * @return void
     */
    public function testUnknownKeysAreReportedBeforeMissingName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document has unknown keys: label.');

        Policy::fromArray(['label' => 'x', 'statements' => []]);
    }

    /**
     * Rejects missing name.
     *
     * @return void
     */
    public function testRejectsMissingName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document requires a non-empty name.');

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
        $this->expectExceptionMessage('Policy document requires a non-empty name.');

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
        $this->expectExceptionMessage('Policy document requires a list of statements.');

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
        $this->expectExceptionMessage('Policy document version must be a positive integer.');

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
        $this->expectExceptionMessage('Policy statements must be associative arrays.');

        // @phpstan-ignore-next-line argument.type
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
        $this->expectExceptionMessage('Policy document version must be a positive integer.');

        // @phpstan-ignore-next-line argument.type
        Policy::fromArray([
            'version'    => '1',
            'name'       => 'x',
            'statements' => [],
        ]);
    }

    /**
     * toArray emits version, name and statements in canonical order (kills the
     * version-key literal mutants).
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
     * Non-string name is rejected.
     *
     * @return void
     */
    public function testRejectsNonStringName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document requires a non-empty name.');

        // @phpstan-ignore-next-line argument.type
        Policy::fromArray(['name' => 42, 'statements' => []]);
    }

    /**
     * Lock the v1 document shape. The fixture exercises every slot — effect,
     * actions, resources, and a condition map with multiple operators — and
     * round-trips it through `fromArray` / `toArray`. If a future schema change
     * alters the canonical layout without bumping `Policy::CURRENT_VERSION`,
     * this test fails loudly and forces the change to land deliberately.
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
     * A negative version is refused as not a positive integer.
     *
     * @return void
     */
    public function testRejectsNegativeVersion(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document version must be a positive integer.');

        Policy::fromArray([
            'version'    => -1,
            'name'       => 'x',
            'statements' => [],
        ]);
    }

    /**
     * An explicit future `version` is refused. The evaluator only understands
     * the current schema, so a document written for a later version must not be
     * evaluated as if it were version 1.
     *
     * @return void
     */
    public function testFutureVersionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy document version 2 is not supported.');

        Policy::fromArray([
            'version'    => 2,
            'name'       => 'forward-compat',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);
    }
}
