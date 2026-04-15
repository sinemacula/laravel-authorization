<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for {@see \SineMacula\Laravel\Authorization\Evaluation\Policy}.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
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
        $this->expectException(InvalidArgumentException::class);

        Policy::fromArray(['statements' => []]);
    }

    /**
     * Rejects empty name.
     *
     * @return void
     */
    public function testRejectsEmptyName(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Policy::fromArray(['name' => '', 'statements' => []]);
    }

    /**
     * Rejects missing statements.
     *
     * @return void
     */
    public function testRejectsMissingStatements(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Policy::fromArray(['name' => 'example']);
    }

    /**
     * Rejects non-integer or non-positive version.
     *
     * @return void
     */
    public function testRejectsInvalidVersion(): void
    {
        $this->expectException(InvalidArgumentException::class);

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
        $this->expectException(InvalidArgumentException::class);

        /** @phpstan-ignore-next-line */
        Policy::fromArray(['name' => 'x', 'statements' => ['not-an-array']]);
    }
}
