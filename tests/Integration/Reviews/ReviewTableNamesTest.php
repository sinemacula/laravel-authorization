<?php

declare(strict_types = 1);

namespace Tests\Integration\Reviews;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Integration tests for access reviews over renamed tables: every grant table,
 * the role permission edges and the break-glass activations read under the
 * names `authorization.tables` gives them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantRows::class)]
final class ReviewTableNamesTest extends TestCase
{
    use ActivatesBreakGlass, ReviewsAccess;

    /** @var list<string> The tables renamed, by their configuration key. */
    private const array TABLES = [
        'roles',
        'permissions',
        'policies',
        'role_permissions',
        'authorizable_roles',
        'authorizable_permissions',
        'authorizable_policies',
        'break_glass',
    ];

    /**
     * Migrate afresh under the renamed tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        RefreshDatabaseState::$migrated = false;

        parent::setUp();
    }

    /**
     * Leave the next test to migrate afresh under its own tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        RefreshDatabaseState::$migrated = false;
    }

    /**
     * Holders, holdings of an action and unused grants are read from the
     * renamed tables, activations paged by their own key as on the default
     * table.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReviewReadsTheRenamedTables(): void
    {
        self::keyCursors();

        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');
        $bob    = self::identity('bob');
        $edit   = self::permission('posts:edit');

        $admin->givePermissionTo($edit);
        self::grants()->grantRole($ann, $editor);
        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->attachPolicy($ann, self::policy('audit'));

        // Each activation gets a lower key than the one before, so only the key
        // orders them.
        foreach ([4, 3, 2, 1] as $key) {
            DB::table('renamed_break_glass')->where('id', self::activate($bob, $editor)->getKey())->update(['id' => '00000000-0000-4000-8000-00000000000' . $key]);
        }

        foreach (self::TABLES as $table) {
            self::assertTrue(Schema::hasTable('renamed_' . $table), $table);
        }

        $holders = ReviewQuery::holders($editor, ReviewScope::everywhere());
        $whole   = self::trusted($holders)->rows;
        $paged   = self::pagedThrough($holders, 1);
        $keys    = static fn (array $rows): array => \array_map(static fn (ReviewRow $row): string => $row->rowKey, $rows);

        self::assertSame(['role_grant ann [editor] editor', ...\array_fill(0, 4, 'role_grant bob [editor] editor (break-glass)')], \array_map(self::describe(...), $whole));
        self::assertSame(
            [null, ...\array_map(static fn (int $key): string => '00000000-0000-4000-8000-00000000000' . $key, [1, 2, 3, 4])],
            \array_map(static fn (ReviewRow $row): mixed => $row->breakGlass['activation'] ?? null, $whole),
        );
        self::assertSame($keys($whole), $keys($paged['rows']));

        // An InnoDB scan already returns activations by key, so the order the
        // query asks for is asserted too.
        self::assertMatchesRegularExpression('/include_subtree asc, (cast\()?renamed_break_glass\.id\b/', \str_replace(['"', '`'], '', \implode("\n", $paged['queries'][0])));
        self::assertCount(5, self::trusted(ReviewQuery::holders($edit, ReviewScope::everywhere()))->rows);
        self::assertSame(
            ['role_permission ann [editor>admin] posts:edit'],
            self::described(self::trusted(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere())->forAction('posts:edit'))),
        );
        self::assertSame(
            [
                'role_grant ann [editor] editor',
                ...\array_fill(0, 4, 'role_grant bob [editor] editor (break-glass)'),
                'permission_grant ann posts:read',
                'policy_attachment ann audit',
            ],
            self::described(self::trusted(ReviewQuery::unused(ReviewScope::everywhere(), Carbon::now()->subYear()))),
        );
    }

    /**
     * Rename every table a review reads.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        foreach (self::TABLES as $table) {
            $config->set('authorization.tables.' . $table, 'renamed_' . $table);
        }
    }
}
