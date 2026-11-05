<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use Tests\TestCase;

/**
 * Feature tests for `PermissionDiffBuilder`, which compares the declared
 * catalogue with the platform's permission rows without touching the database.
 *
 * The rows are unsaved models; only the model's constructor needs the
 * application, for the configured table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionDiffBuilder::class)]
#[CoversClass(PermissionDiff::class)]
#[CoversClass(PermissionDefinition::class)]
final class PermissionDiffBuilderTest extends TestCase
{
    /**
     * A declared permission with no row is to be added.
     *
     * @return void
     */
    public function testADeclaredPermissionWithoutARowIsAdded(): void
    {
        $definition = new PermissionDefinition(name: 'posts:create', description: 'Create posts');

        $diff = (new PermissionDiffBuilder)->build([$definition], []);

        self::assertSame([$definition], $diff->add);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->stale);
        self::assertSame([], $diff->protected);
        self::assertSame([], $diff->unchanged);
    }

    /**
     * A row whose description or category differs from its declaration is to be
     * updated, paired with the definition.
     *
     * @return void
     */
    public function testARowWithDifferentMetadataIsUpdated(): void
    {
        $definition  = new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts');
        $description = self::row('posts:create', null, description: 'Write posts', category: 'Posts');
        $category    = self::row('posts:create', 'web', description: 'Create posts', category: 'Content');

        $webDefinition = new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts', guard: 'web');

        $diff = (new PermissionDiffBuilder)->build([$webDefinition, $definition], [$category, $description]);

        self::assertSame(
            [['row' => $description, 'definition' => $definition], ['row' => $category, 'definition' => $webDefinition]],
            $diff->update,
        );
        self::assertSame([], $diff->add);
        self::assertSame([], $diff->unchanged);
    }

    /**
     * A row matching its declaration is unchanged, even when marked system.
     *
     * @return void
     */
    public function testAMatchingRowIsUnchanged(): void
    {
        $row    = self::row('posts:create', null, description: 'Create posts');
        $system = self::row('posts:delete', null, system: true);

        $diff = (new PermissionDiffBuilder)->build(
            [new PermissionDefinition('posts:delete'), new PermissionDefinition(name: 'posts:create', description: 'Create posts')],
            [$system, $row],
        );

        self::assertSame([$row, $system], $diff->unchanged);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->protected);
    }

    /**
     * An undeclared row is stale, and protected instead when marked system.
     *
     * @return void
     */
    public function testAnUndeclaredRowIsStaleOrProtected(): void
    {
        $stale  = self::row('posts:archive', null);
        $system = self::row('posts:purge', null, system: true);

        $diff = (new PermissionDiffBuilder)->build([], [$system, $stale]);

        self::assertSame([$stale], $diff->stale);
        self::assertSame([$system], $diff->protected);
    }

    /**
     * A system row declared with different metadata is protected, not updated,
     * since a system row refuses every edit.
     *
     * @return void
     */
    public function testADeclaredSystemRowWithDifferentMetadataIsProtected(): void
    {
        $system = self::row('posts:purge', null, description: 'Purge posts', system: true);

        $diff = (new PermissionDiffBuilder)->build([new PermissionDefinition(name: 'posts:purge', description: 'Delete every post')], [$system]);

        self::assertSame([$system], $diff->protected);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->stale);
    }

    /**
     * A row matches only the definition with the same guard: a guard-specific
     * row neither matches a guard-agnostic definition nor stops it being added.
     *
     * @return void
     */
    public function testMatchesOnTheNameAndTheGuard(): void
    {
        $row        = self::row('posts:create', 'web');
        $definition = new PermissionDefinition('posts:create');

        $diff = (new PermissionDiffBuilder)->build([$definition], [$row]);

        self::assertSame([$definition], $diff->add);
        self::assertSame([$row], $diff->stale);
    }

    /**
     * Every list is ordered by name, then guard, guard-agnostic first.
     *
     * @return void
     */
    public function testOrdersEveryListByNameThenGuard(): void
    {
        $api      = new PermissionDefinition(name: 'b:edit', guard: 'api');
        $agnostic = new PermissionDefinition('b:edit');
        $first    = new PermissionDefinition('a:edit');

        $staleWeb  = self::row('d:edit', 'web');
        $staleAny  = self::row('d:edit', null);
        $staleLast = self::row('e:edit', null);

        $diff = (new PermissionDiffBuilder)->build([$api, $agnostic, $first], [$staleLast, $staleWeb, $staleAny]);

        self::assertSame([$first, $agnostic, $api], $diff->add);
        self::assertSame([$staleAny, $staleWeb, $staleLast], $diff->stale);
    }

    /**
     * Protected and unchanged rows are ordered too.
     *
     * @return void
     */
    public function testOrdersProtectedAndUnchangedRows(): void
    {
        $protectedLast  = self::row('z:edit', null, system: true);
        $protectedFirst = self::row('y:edit', null, system: true);
        $unchangedLast  = self::row('c:edit', null);
        $unchangedFirst = self::row('b:edit', null);

        $diff = (new PermissionDiffBuilder)->build(
            [new PermissionDefinition('c:edit'), new PermissionDefinition('b:edit')],
            [$protectedLast, $unchangedLast, $protectedFirst, $unchangedFirst],
        );

        self::assertSame([$protectedFirst, $protectedLast], $diff->protected);
        self::assertSame([$unchangedFirst, $unchangedLast], $diff->unchanged);
    }

    /**
     * Updated pairs are ordered by name, then guard.
     *
     * @return void
     */
    public function testOrdersUpdatedPairs(): void
    {
        $lastRow         = self::row('b:edit', null, description: 'old');
        $firstRow        = self::row('a:edit', null, description: 'old');
        $lastDefinition  = new PermissionDefinition(name: 'b:edit', description: 'new');
        $firstDefinition = new PermissionDefinition(name: 'a:edit', description: 'new');

        $diff = (new PermissionDiffBuilder)->build([$lastDefinition, $firstDefinition], [$lastRow, $firstRow]);

        self::assertSame(
            [['row' => $firstRow, 'definition' => $firstDefinition], ['row' => $lastRow, 'definition' => $lastDefinition]],
            $diff->update,
        );
    }

    /**
     * Build an unsaved platform permission row.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  string|null  $category
     * @param  bool  $system
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function row(string $name, ?string $guard, ?string $description = null, ?string $category = null, bool $system = false): Permission
    {
        return (new Permission)->forceFill([
            'name'        => $name,
            'guard'       => $guard,
            'description' => $description,
            'category'    => $category,
            'is_system'   => $system,
        ]);
    }
}
