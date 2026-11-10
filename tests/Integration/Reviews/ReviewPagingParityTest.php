<?php

declare(strict_types = 1);

namespace Tests\Integration\Reviews;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Parity of the ways an access review is read (AUTHZ-11.6, N98): on the same
 * data, the whole review, its pages read to the end at every page size, its
 * stream at every chunk size and its export give the same rows in the same
 * order, with no duplicate and none left out, for every query and scope, over
 * alternative routes through a hierarchy, nullable scopes, rows naming half a
 * tenant and references differing only in case, a trailing space, accents or
 * symbols, on every database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AccessReview::class)]
final class ReviewPagingParityTest extends TestCase
{
    use ReviewsAccess;

    /** @var list<string> Grantee keys that differ only in case, a trailing space, accents or symbols. */
    private const array KEYS = ['b', 'B', 'a ', 'a', "\u{e4}", "\u{1f600}", 'a\'b', '10', '9', 'a%_'];

    /**
     * Every query in every scope reads the same rows in the same order whole,
     * paged, streamed and exported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPagesStreamsAndExportsReadTheWholeReview(): void
    {
        self::keyCursors();

        $this->tree();

        [$queries, $scopes] = $this->seedTheReview();

        foreach ($scopes as $name => $scope) {
            foreach ($queries as $kind => $query) {
                $label = "{$kind} in {$name}";
                $whole = self::keys(self::trusted($query($scope)->withLimit(100000))->rows);

                self::assertSame(\array_values(\array_unique($whole)), $whole, "{$label} lists a row twice.");
                self::assertTrue($name !== 'everywhere' || \count($whole) > 3, "{$label} lists too few rows to page.");

                foreach ([1, 2, 3, 7] as $size) {
                    self::assertSame($whole, self::paged($query($scope), $size), "{$label} paged by {$size}");
                    self::assertSame($whole, self::keys([...self::reviews()->trustedStream($query($scope), $size)]), "{$label} streamed by {$size}");
                }

                self::assertSame($whole, self::exported($query($scope), 2), "{$label} exported");
            }
        }
    }

    /**
     * A role, permission or policy named by its key in capitals reads the same
     * holders, through the same routes, whole, paged and streamed, as one named
     * in the stored lowercase form, on every database: every page resumes from
     * the key its grant stores, never from the query's spelling.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATargetNamedInCapitalsReadsTheSameHolders(): void
    {
        self::keyCursors();

        $top        = self::role('top');
        $leaf       = self::role('leaf', $top);
        $permission = self::permission('posts:edit');
        $policy     = self::policy('deny-delete');

        self::roles()->grantPermission($top, $permission);
        self::grants()->attachPolicy($top, $policy);

        foreach (['g1', 'g2', 'g3', 'g4', 'g5'] as $key) {
            self::grants()->grantRole(new Reference('u', $key), $top);
            self::grants()->grantPermission(new Reference('u', $key), $permission);
            self::grants()->attachPolicy(new Reference('u', $key), $policy);
        }

        foreach (['h1', 'h2'] as $key) {
            self::grants()->grantRole(new Reference('u', $key), $leaf);
        }

        foreach ([[$top, 7], [$permission, 12], [$policy, 12]] as [$definition, $count]) {
            $stored  = Reference::of($definition);
            $capital = ReviewQuery::holders(new Reference($stored->type, \strtoupper($stored->id)), ReviewScope::everywhere());
            $whole   = self::keys(self::trusted(ReviewQuery::holders($stored, ReviewScope::everywhere()))->rows);

            self::assertCount($count, $whole, $stored->type);
            self::assertSame($whole, self::keys(self::trusted($capital)->rows), $stored->type);

            foreach ([1, 2, 3] as $size) {
                self::assertSame($whole, self::paged($capital, $size), "{$stored->type} paged by {$size}");
                self::assertSame($whole, self::keys([...self::reviews()->trustedStream($capital, $size)]), "{$stored->type} streamed by {$size}");
            }
        }
    }

    /**
     * A review reached through a hierarchy hundreds of roles deep is paged to
     * its end, one row a page, every cursor short, however long the routes its
     * rows run through: the holders of the top role and of a permission carried
     * along the chain, and what a holder of the lowest role holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeepHierarchyIsPagedToItsEnd(): void
    {
        self::keyCursors();

        $roles      = self::chainOf(300);
        $permission = self::permission('posts:edit');

        foreach ([0, 150, 299] as $level) {
            self::roles()->grantPermission($roles[$level], $permission);
        }

        foreach (['a', 'b', 'c'] as $key) {
            self::grants()->grantRole(new Reference('u', $key), $roles[299]);
        }

        $queries = [
            'holders of the top role'   => ReviewQuery::holders($roles[0], ReviewScope::everywhere()),
            'holders of the permission' => ReviewQuery::holders($permission, ReviewScope::everywhere()),
            'holdings of a holder'      => ReviewQuery::holdings(new Reference('u', 'a'), ReviewScope::everywhere()),
        ];

        $counts = ['holders of the top role' => 3, 'holders of the permission' => 9, 'holdings of a holder' => 303];

        foreach ($queries as $label => $query) {
            $whole = self::keys(self::trusted($query->withLimit(100000))->rows);

            self::assertCount($counts[$label], $whole, $label);
            self::assertSame($whole, self::paged($query, 1), "{$label} paged by 1");
            self::assertSame($whole, self::keys([...self::reviews()->trustedStream($query, 2)]), "{$label} streamed by 2");
        }
    }

    /**
     * Seed a hierarchy, the permission and policies it carries, and grants of
     * each in every kind of scope to grantees with unusual references, some
     * naming half a tenant, some expiring and some written by an actor; and
     * return the queries and the scopes to read them in.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return array{array<string, \Closure(\SineMacula\Laravel\Authorization\Reviews\ReviewScope): \SineMacula\Laravel\Authorization\Reviews\ReviewQuery>, array<string, \SineMacula\Laravel\Authorization\Reviews\ReviewScope>}
     *
     * @throws \Throwable
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    private function seedTheReview(): array
    {
        $top        = self::role('top');
        $mid        = self::role('mid', $top);
        $leaf       = self::role('leaf', $mid);
        $permission = self::permission('posts:edit');
        $policy     = self::policy('deny-delete');
        $actor      = new Reference('actor', 'writer');
        $soon       = CarbonImmutable::now('UTC')->addWeek()->startOfSecond();

        self::roles()->grantPermission($top, $permission);
        self::roles()->grantPermission($mid, $permission);
        self::grants()->attachPolicy($top, $policy);
        self::grants()->attachPolicy($mid, $policy, tenant: self::tenant('org1'));

        $scopes = [
            [null, true, null],
            [self::tenant('org1'), true, null],
            [self::tenant('acct1'), false, 'web'],
            [self::tenant('team1'), true, null],
        ];

        foreach (self::KEYS as $index => $key) {
            $grantee = new Reference($index % 2 === 0 ? 'odd type' : 'other type', $key);

            foreach ($scopes as $position => [$tenant, $subtree, $application]) {
                $expiry = ($index + $position) % 3 === 0 ? $soon : null;

                self::grants()->grantRole($grantee, [$top, $mid, $leaf][($index + $position) % 3], $expiry, tenant: $tenant, includeSubtree: $subtree, application: $application);
                self::grants()->grantPermission($grantee, $permission, $expiry, tenant: $tenant, includeSubtree: $subtree, application: $application);
            }

            self::grants()->attachPolicy($grantee, $policy, $soon, tenant: self::tenant('acct1'));
        }

        DB::table('authorizable_roles')->where('authorizable_id', 'a')->where('tenant_id', 'org1')->update(['tenant_type' => null]);
        DB::table('authorizable_permissions')->where('authorizable_id', 'B')->where('tenant_id', 'acct1')->update(['tenant_id' => null]);
        DB::table('authorizable_roles')->where('authorizable_type', 'odd type')->update(['granted_by_type' => $actor->type, 'granted_by_id' => $actor->id]);
        DB::table('authorizable_permissions')->where('authorizable_id', '9')->update(['granted_by_type' => $actor->type, 'granted_by_id' => $actor->id]);

        $ann = self::identity('ann');

        self::grants()->grantRole($ann, $leaf, $soon);
        self::grants()->grantRole($ann, $mid, tenant: self::tenant('acct1'), application: 'web');
        self::grants()->grantPermission($ann, $permission, tenant: self::tenant('org1'));

        $queries = [
            'holders of a role'          => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holders($top, $scope),
            'holders of a middle role'   => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holders($mid, $scope),
            'direct holders'             => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holders($top, $scope, true),
            'holders of a permission'    => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holders($permission, $scope),
            'holders of a policy'        => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holders($policy, $scope),
            'holdings of a subject'      => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holdings(new Subject($ann, $ann), $scope),
            'holdings of a grantee'      => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::holdings(new Reference('other type', 'a'), $scope),
            'expiring grants'            => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::expiring($scope, $soon->subDay(), $soon->addDay()),
            'grants written by an actor' => static fn (ReviewScope $scope): ReviewQuery => ReviewQuery::grantedBy($actor, $scope),
        ];

        $reviewed = [
            'everywhere'      => ReviewScope::everywhere(),
            'an account'      => ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::any()),
            'an application'  => ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::named('web')),
            'the platform'    => ReviewScope::appliesIn(null, ApplicationSelector::none()),
            'an organisation' => ReviewScope::rootedWithin(self::tenant('org1')),
        ];

        return [$queries, $reviewed];
    }

    /**
     * Return a chain of the given number of roles, the first at the top and
     * each below the one before, written straight to the roles table.
     *
     * @param  int  $depth
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function chainOf(int $depth): array
    {
        $now    = CarbonImmutable::now('UTC')->format('Y-m-d H:i:s');
        $rows   = [];
        $parent = null;

        for ($level = 0; $level < $depth; $level++) {
            $key    = Str::uuid()->toString();
            $rows[] = ['id' => $key, 'name' => 'level-' . $level, 'parent_id' => $parent, 'is_system' => false, 'created_at' => $now, 'updated_at' => $now];
            $parent = $key;
        }

        foreach (\array_chunk($rows, 100) as $chunk) {
            DB::table('roles')->insert($chunk);
        }

        $roles = [];

        foreach (\array_column($rows, 'id') as $key) {
            $roles[] = Role::query()->whereKey($key)->firstOrFail();
        }

        return $roles;
    }

    /**
     * Return the row keys of every page of the review read as trusted work, at
     * most the size of them a page, from its first page to its last, every
     * cursor short.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  int  $size
     * @return list<string>
     *
     * @throws \Throwable
     */
    private static function paged(ReviewQuery $query, int $size): array
    {
        $keys   = [];
        $cursor = null;
        $pages  = 0;

        do {
            $page = self::reviews()->trustedPage($query, $cursor, $size);

            self::assertLessThanOrEqual($size, \count($page->rows));

            \array_push($keys, ...self::keys($page->rows));

            $cursor = $page->nextCursor;
            $pages++;

            self::assertLessThan(2048, \strlen($cursor ?? ''), 'A cursor grew with the review.');
        } while ($cursor !== null && $pages < 10000);

        return $keys;
    }

    /**
     * Return the row keys of the review's export as trusted work, read a chunk
     * of the size at a time, checking its header and footer.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  int  $chunk
     * @return list<string>
     *
     * @throws \Throwable
     */
    private static function exported(ReviewQuery $query, int $chunk): array
    {
        $lines = [];

        $written = self::reviews()->trustedExport($query, static function (string $line) use (&$lines): void {
            $lines[] = \json_decode($line, true, 512, \JSON_THROW_ON_ERROR);
        }, $chunk);

        $header = \array_shift($lines);
        $footer = \array_pop($lines);

        self::assertSame(['header', 'footer', $written], [$header['record'] ?? null, $footer['record'] ?? null, $footer['rows'] ?? null]);

        $keys = [];

        foreach ($lines as $line) {
            self::assertIsArray($line);
            self::assertIsString($line['row_key'] ?? null);

            $keys[] = $line['row_key'];
        }

        return $keys;
    }

    /**
     * Return the keys of the rows, in their order.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @return list<string>
     */
    private static function keys(array $rows): array
    {
        return \array_map(static fn (ReviewRow $row): string => $row->rowKey, $rows);
    }
}
