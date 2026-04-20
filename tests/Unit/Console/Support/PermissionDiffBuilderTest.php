<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Console\Support\PermissionTuple;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Unit tests for the pure-function permission diff engine.
 *
 * Each test constructs `PermissionTuple` expectations alongside in-memory
 * `Permission` rows (no DB writes) and asserts bucket assignment. Bucket
 * ordering is also exercised so downstream sync output stays deterministic.
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
#[CoversClass(PermissionTuple::class)]
final class PermissionDiffBuilderTest extends TestCase
{
    /**
     * Bind a minimal Laravel container with a `config` binding so the
     * `Permission` model constructor — which reads
     * `authorization.tables.permissions` — resolves without booting the full
     * framework.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $container = new Container;
        $container->instance('config', new ConfigRepository([
            'authorization' => ['tables' => ['permissions' => 'permissions']],
        ]));

        Container::setInstance($container);
    }

    /**
     * Reset the static container reference after each test so doubles do not
     * leak between suites.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * A tuple with no matching row lands in the `add` bucket.
     *
     * @return void
     */
    public function testTupleWithoutRowLandsInAdd(): void
    {
        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Content',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [], 0);

        self::assertSame([$tuple], $diff->add);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->reinstate);
        self::assertSame([], $diff->retire);
        self::assertSame([], $diff->protected);
        self::assertSame([], $diff->unchanged);
    }

    /**
     * A tuple matching a row with identical metadata and no deprecation lands
     * in `unchanged`.
     *
     * @return void
     */
    public function testMatchingRowWithIdenticalMetadataIsUnchanged(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Content',
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Content',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertSame([$row], $diff->unchanged);
        self::assertSame([], $diff->add);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->reinstate);
    }

    /**
     * A tuple whose description differs from its matching row lands in
     * `update`.
     *
     * @return void
     */
    public function testDescriptionDriftProducesUpdate(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: 'web',
            description: 'Old description',
            category: 'Content',
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'New description',
            category: 'Content',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertCount(1, $diff->update);
        self::assertSame($row, $diff->update[0]['row']);
        self::assertSame($tuple, $diff->update[0]['tuple']);
        self::assertSame([], $diff->unchanged);
    }

    /**
     * A tuple whose category differs from its matching row lands in `update`.
     *
     * @return void
     */
    public function testCategoryDriftProducesUpdate(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Old category',
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'New category',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertCount(1, $diff->update);
        self::assertSame($row, $diff->update[0]['row']);
        self::assertSame($tuple, $diff->update[0]['tuple']);
    }

    /**
     * A tuple matching a deprecated row lands in `reinstate` regardless of
     * whether metadata drifts — reinstating always refreshes the metadata
     * alongside clearing `deprecated_at`.
     *
     * @return void
     */
    public function testDeprecatedRowMatchLandsInReinstate(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Content',
            deprecatedAt: CarbonImmutable::now(),
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'Create posts',
            category: 'Content',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertCount(1, $diff->reinstate);
        self::assertSame($row, $diff->reinstate[0]['row']);
        self::assertSame($tuple, $diff->reinstate[0]['tuple']);
        self::assertSame([], $diff->update);
        self::assertSame([], $diff->unchanged);
    }

    /**
     * A deprecated row with drifted metadata still lands in `reinstate` only —
     * never in `update` — so the caller applies clear-and-refresh semantics
     * once.
     *
     * @return void
     */
    public function testDeprecatedRowWithMetadataDriftIsOnlyReinstate(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: 'web',
            description: 'Old description',
            category: 'Old category',
            deprecatedAt: CarbonImmutable::now(),
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: 'web',
            description: 'New description',
            category: 'New category',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertCount(1, $diff->reinstate);
        self::assertSame([], $diff->update);
    }

    /**
     * A row with no matching tuple and `is_system = false` lands in `retire`.
     *
     * @return void
     */
    public function testRowWithoutTupleAndNotSystemLandsInRetire(): void
    {
        $row = $this->makeRow(name: 'posts:create', guard: 'web');

        $diff = (new PermissionDiffBuilder)->build([], [$row], 0);

        self::assertSame([$row], $diff->retire);
        self::assertSame([], $diff->protected);
    }

    /**
     * A row with no matching tuple and `is_system = true` lands in `protected`
     * — sync reports these but never retires them.
     *
     * @return void
     */
    public function testRowWithoutTupleAndSystemLandsInProtected(): void
    {
        $row = $this->makeRow(name: 'posts:create', guard: 'web', isSystem: true);

        $diff = (new PermissionDiffBuilder)->build([], [$row], 0);

        self::assertSame([$row], $diff->protected);
        self::assertSame([], $diff->retire);
    }

    /**
     * A null guard on the tuple matches a null guard on the row — and matches
     * an empty-string guard too (normalisation).
     *
     * @return void
     */
    public function testNullAndEmptyStringGuardsCollapseToSameKey(): void
    {
        $row = $this->makeRow(
            name: 'posts:create',
            guard: '',
            description: 'Create posts',
            category: 'Content',
        );

        $tuple = new PermissionTuple(
            name: 'posts:create',
            guard: null,
            description: 'Create posts',
            category: 'Content',
        );

        $diff = (new PermissionDiffBuilder)->build([$tuple], [$row], 0);

        self::assertSame([$row], $diff->unchanged);
    }

    /**
     * A mixed scenario populates every bucket and propagates the
     * `roleReferencesCount` to the output.
     *
     * @return void
     */
    public function testMixedScenarioPopulatesEveryBucket(): void
    {
        // Unchanged: matches tuple, no drift, live.
        $unchangedRow   = $this->makeRow(name: 'a:read', guard: 'web', description: 'Read A', category: 'A');
        $unchangedTuple = new PermissionTuple('a:read', 'web', 'Read A', 'A');

        // Update: matches tuple, metadata drifts, live.
        $updateRow   = $this->makeRow(name: 'b:edit', guard: 'web', description: 'Old', category: 'B');
        $updateTuple = new PermissionTuple('b:edit', 'web', 'New', 'B');

        // Reinstate: matches tuple, deprecated.
        $reinstateRow = $this->makeRow(
            name: 'c:view',
            guard: 'web',
            description: 'View C',
            category: 'C',
            deprecatedAt: CarbonImmutable::now(),
        );
        $reinstateTuple = new PermissionTuple('c:view', 'web', 'View C', 'C');

        // Retire: no tuple, not system.
        $retireRow = $this->makeRow(name: 'd:delete', guard: 'web');

        // Protected: no tuple, system.
        $protectedRow = $this->makeRow(name: 'e:system', guard: 'web', isSystem: true);

        // Add: tuple without a matching row.
        $addTuple = new PermissionTuple('f:create', 'web', 'Create F', 'F');

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [$unchangedTuple, $updateTuple, $reinstateTuple, $addTuple],
            rows: [$unchangedRow, $updateRow, $reinstateRow, $retireRow, $protectedRow],
            roleReferencesCount: 3,
        );

        self::assertSame([$addTuple], $diff->add);
        self::assertSame([$updateRow], array_column($diff->update, 'row'));
        self::assertSame([$reinstateRow], array_column($diff->reinstate, 'row'));
        self::assertSame([$retireRow], $diff->retire);
        self::assertSame([$protectedRow], $diff->protected);
        self::assertSame([$unchangedRow], $diff->unchanged);
        self::assertSame(3, $diff->roleReferencesCount);
    }

    /**
     * Every bucket is sorted by `(name, guard)` ascending with null guards
     * sorted first within a given name, and concrete guards sort between
     * themselves by `strcmp` — `api` ahead of `web`.
     *
     * @return void
     */
    public function testBucketsAreSortedByNameGuardWithNullFirst(): void
    {
        $tupleZ     = new PermissionTuple('z:alpha', 'web', null, null);
        $tupleAWeb  = new PermissionTuple('a:alpha', 'web', null, null);
        $tupleAApi  = new PermissionTuple('a:alpha', 'api', null, null);
        $tupleANull = new PermissionTuple('a:alpha', null, null, null);

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [$tupleZ, $tupleAWeb, $tupleAApi, $tupleANull],
            rows: [],
            roleReferencesCount: 0,
        );

        // Null first, then concrete guards alphabetically (api < web), then z:*
        // after a:*. Exercises every compareGuards branch: equal (never hit
        // here, no duplicates), null-left, null-right, and two concrete guards
        // falling through to strcmp.
        self::assertSame([$tupleANull, $tupleAApi, $tupleAWeb, $tupleZ], $diff->add);
    }

    /**
     * `sortPairs` actually sorts the pair lists — an update bucket with
     * multiple entries comes back ordered by the tuple's `(name, guard)` even
     * when the input was shuffled. Guards null sort first within a given name;
     * concrete guards sort by `strcmp`.
     *
     * @return void
     */
    public function testUpdatePairsAreSortedByTupleNameAndGuard(): void
    {
        $rowZ     = $this->makeRow(name: 'z:edit', guard: 'web', description: 'old', category: 'Z');
        $rowAWeb  = $this->makeRow(name: 'a:edit', guard: 'web', description: 'old', category: 'A');
        $rowAApi  = $this->makeRow(name: 'a:edit', guard: 'api', description: 'old', category: 'A');
        $rowANull = $this->makeRow(name: 'a:edit', guard: null, description: 'old', category: 'A');

        $tupleZ     = new PermissionTuple('z:edit', 'web', 'new', 'Z');
        $tupleAWeb  = new PermissionTuple('a:edit', 'web', 'new', 'A');
        $tupleAApi  = new PermissionTuple('a:edit', 'api', 'new', 'A');
        $tupleANull = new PermissionTuple('a:edit', null, 'new', 'A');

        // Intentionally scrambled input order so the sort is actually exercised
        // rather than preserving ingestion order.
        $diff = (new PermissionDiffBuilder)->build(
            tuples: [$tupleZ, $tupleAApi, $tupleANull, $tupleAWeb],
            rows: [$rowZ, $rowAApi, $rowANull, $rowAWeb],
            roleReferencesCount: 0,
        );

        self::assertCount(4, $diff->update);
        self::assertSame(
            [$rowANull, $rowAApi, $rowAWeb, $rowZ],
            array_column($diff->update, 'row'),
        );
        self::assertSame(
            [$tupleANull, $tupleAApi, $tupleAWeb, $tupleZ],
            array_column($diff->update, 'tuple'),
        );
    }

    /**
     * Composite keys must embed a non-printable `\0` separator between `name`
     * and `guard`; otherwise `('posts:view', null)` would collide with
     * `('posts', ':view')` via naive string concatenation. A row whose `(name,
     * guard)` differs from the tuple only at the separator boundary must NOT
     * match the tuple: the tuple belongs in `add`, the row belongs in `retire`.
     *
     * @return void
     */
    public function testCompositeKeyDoesNotCollideAcrossNameGuardBoundary(): void
    {
        // Row and tuple would concatenate to the same `posts:view` string
        // without the null-byte separator, but must compose to distinct match
        // keys under the real separator.
        $row   = $this->makeRow(name: 'posts:view', guard: null);
        $tuple = new PermissionTuple(name: 'posts', guard: ':view', description: 'one', category: 'A');

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [$tuple],
            rows: [$row],
            roleReferencesCount: 0,
        );

        self::assertSame([$tuple], $diff->add);
        self::assertSame([$row], $diff->retire);
        self::assertSame([], $diff->unchanged);
        self::assertSame([], $diff->update);
    }

    /**
     * A retire row surfaces when it follows a system (protected) row in the
     * input order — the per-row loop must `continue` past a protected row
     * rather than `break` out of the partition pass.
     *
     * @return void
     */
    public function testRetireRowAfterProtectedRowStillLandsInRetire(): void
    {
        $systemRow = $this->makeRow(name: 'a:system', guard: 'web', isSystem: true);
        $retireRow = $this->makeRow(name: 'b:retire', guard: 'web');

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [],
            rows: [$systemRow, $retireRow],
            roleReferencesCount: 0,
        );

        self::assertSame([$systemRow], $diff->protected);
        self::assertSame([$retireRow], $diff->retire);
    }

    /**
     * A matched (unchanged) row followed by an unmatched non-system row
     * surfaces only the latter in `retire` — proves the matched bookkeeping
     * (`$matchedKeys[$key] = true`) is in lockstep with the second pass, so the
     * matched row is not re-partitioned as retire.
     *
     * @return void
     */
    public function testMatchedRowIsNeverRePartitionedAsRetire(): void
    {
        $matchedRow = $this->makeRow(
            name: 'a:read',
            guard: 'web',
            description: 'Read A',
            category: 'A',
        );
        $retireRow = $this->makeRow(name: 'b:retire', guard: 'web');

        $tuple = new PermissionTuple('a:read', 'web', 'Read A', 'A');

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [$tuple],
            rows: [$matchedRow, $retireRow],
            roleReferencesCount: 0,
        );

        self::assertSame([$matchedRow], $diff->unchanged);
        self::assertSame([$retireRow], $diff->retire);
        self::assertSame([], $diff->protected);
        self::assertNotContains($matchedRow, $diff->retire);
    }

    /**
     * Two tuples sharing an identical `(name, guard)` pair — as would arise if
     * separate enum classes declared the same backing value under the same
     * guard — both land in `add`. The sort comparator hits the equal-guards
     * branch in `compareGuards()` and returns a stable zero so neither tuple is
     * dropped.
     *
     * @return void
     */
    public function testEqualTuplesShareBucketWithoutDeduplication(): void
    {
        $first  = new PermissionTuple('posts:create', 'web', 'Create posts', 'Content');
        $second = new PermissionTuple('posts:create', 'web', 'Create posts', 'Content');

        $diff = (new PermissionDiffBuilder)->build([$first, $second], [], 0);

        self::assertCount(2, $diff->add);
        self::assertContains($first, $diff->add);
        self::assertContains($second, $diff->add);
    }

    /**
     * The `retire` bucket is sorted deterministically — namespace `b` sorts
     * ahead of `z`, and within a name, null guards sort ahead of concrete
     * guards.
     *
     * @return void
     */
    public function testRetireBucketIsSortedDeterministically(): void
    {
        $rowZ     = $this->makeRow(name: 'z:remove', guard: 'web');
        $rowBWeb  = $this->makeRow(name: 'b:remove', guard: 'web');
        $rowBNull = $this->makeRow(name: 'b:remove', guard: null);

        $diff = (new PermissionDiffBuilder)->build(
            tuples: [],
            rows: [$rowZ, $rowBWeb, $rowBNull],
            roleReferencesCount: 0,
        );

        self::assertSame([$rowBNull, $rowBWeb, $rowZ], $diff->retire);
    }

    /**
     * Hydrate a `Permission` model without writing to the database and without
     * triggering any Eloquent cast that would otherwise require a bound
     * connection resolver. `setRawAttributes` stores the raw payload verbatim;
     * the diff engine reads the cast `deprecated_at` value and the boolean
     * `is_system` flag, and both are supplied in their cast-friendly native
     * form here (`CarbonImmutable` and `bool`).
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  string|null  $category
     * @param  bool  $isSystem
     * @param  \Carbon\CarbonImmutable|null  $deprecatedAt
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function makeRow(
        string $name,
        ?string $guard,
        ?string $description = null,
        ?string $category = null,
        bool $isSystem = false,
        ?CarbonImmutable $deprecatedAt = null,
    ): Permission {
        $permission = new Permission;
        $permission->setRawAttributes([
            'name'          => $name,
            'guard'         => $guard,
            'description'   => $description,
            'category'      => $category,
            'is_system'     => $isSystem,
            'deprecated_at' => $deprecatedAt,
        ]);

        return $permission;
    }
}
