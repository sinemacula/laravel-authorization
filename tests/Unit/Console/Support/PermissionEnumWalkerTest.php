<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Console\Support\PermissionEnumWalker;
use SineMacula\Laravel\Authorization\Console\Support\PermissionTuple;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use Tests\Unit\Console\Support\Stubs\EmptyGuardsPermission;
use Tests\Unit\Console\Support\Stubs\MetadataOnlyPermission;
use Tests\Unit\Console\Support\Stubs\MultiGuardPermission;
use Tests\Unit\Console\Support\Stubs\NoAttributePermission;
use Tests\Unit\Console\Support\Stubs\SecondaryPermission;
use Tests\Unit\Console\Support\Stubs\SingleGuardPermission;

/**
 * Unit tests for the permission enum walker.
 *
 * Each test exercises a specific attribute shape against a dedicated fixture
 * enum so the cases do not interfere and the failure output names the scenario
 * directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionEnumWalker::class)]
#[CoversClass(PermissionTuple::class)]
#[CoversClass(InvalidPermissionAttributeException::class)]
final class PermissionEnumWalkerTest extends TestCase
{
    /**
     * A case with no `#[Permission]` attribute yields a single guard-agnostic
     * tuple and all-null metadata.
     *
     * @return void
     */
    public function testCaseWithoutAttributeYieldsSingleNullGuardTuple(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        $tuples = $walker->walk([NoAttributePermission::class]);

        self::assertCount(1, $tuples);
        self::assertSame('applications:delete', $tuples[0]->name);
        self::assertNull($tuples[0]->guard);
        self::assertNull($tuples[0]->description);
        self::assertNull($tuples[0]->category);
    }

    /**
     * A case with description and category but no `guards` argument yields a
     * single guard-agnostic tuple carrying the populated metadata.
     *
     * @return void
     */
    public function testAttributeWithoutGuardsYieldsSingleGuardAgnosticTuple(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        $tuples = $walker->walk([MetadataOnlyPermission::class]);

        self::assertCount(1, $tuples);
        self::assertSame('posts:edit', $tuples[0]->name);
        self::assertNull($tuples[0]->guard);
        self::assertSame('Edit posts', $tuples[0]->description);
        self::assertSame('Content', $tuples[0]->category);
    }

    /**
     * A single-guard attribute expands to one tuple carrying the supplied
     * guard.
     *
     * @return void
     */
    public function testSingleGuardAttributeYieldsSingleTupleWithGuard(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        $tuples = $walker->walk([SingleGuardPermission::class]);

        self::assertCount(1, $tuples);
        self::assertSame('posts:publish', $tuples[0]->name);
        self::assertSame('web', $tuples[0]->guard);
        self::assertSame('Publish posts', $tuples[0]->description);
        self::assertSame('Content', $tuples[0]->category);
    }

    /**
     * A multi-guard attribute expands to one tuple per guard, each carrying the
     * same metadata.
     *
     * @return void
     */
    public function testMultiGuardAttributeExpandsToOneTuplePerGuard(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        $tuples = $walker->walk([MultiGuardPermission::class]);

        self::assertCount(2, $tuples);
        self::assertSame('applications:view', $tuples[0]->name);
        self::assertSame('web', $tuples[0]->guard);
        self::assertSame('applications:view', $tuples[1]->name);
        self::assertSame('api', $tuples[1]->guard);
        self::assertSame('View applications', $tuples[0]->description);
        self::assertSame('Applications', $tuples[1]->category);
    }

    /**
     * An explicit `guards: []` configuration raises
     * `InvalidPermissionAttributeException` naming both the enum class and the
     * offending case.
     *
     * @return void
     */
    public function testEmptyGuardsArrayRaisesInvalidAttributeException(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        try {
            $walker->walk([EmptyGuardsPermission::class]);
            self::fail('Expected InvalidPermissionAttributeException.');
        } catch (InvalidPermissionAttributeException $exception) {
            self::assertSame(EmptyGuardsPermission::class, $exception->getEnumClass());
            self::assertSame('BROKEN', $exception->getCaseName());
            self::assertStringContainsString(EmptyGuardsPermission::class, $exception->getMessage());
            self::assertStringContainsString('BROKEN', $exception->getMessage());
        }
    }

    /**
     * Multiple enums passed to a single walk aggregate their tuples in the
     * input order of the enum list.
     *
     * @return void
     */
    public function testMultipleEnumsAggregateIntoSingleTupleList(): void
    {
        $walker = new PermissionEnumWalker(new PermissionMetadataReader);

        $tuples = $walker->walk([
            MetadataOnlyPermission::class,
            SecondaryPermission::class,
        ]);

        self::assertCount(2, $tuples);
        self::assertSame('posts:edit', $tuples[0]->name);
        self::assertSame('roles:assign', $tuples[1]->name);
    }
}
