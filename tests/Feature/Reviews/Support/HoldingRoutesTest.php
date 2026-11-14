<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\HoldingRoutes;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\TestCase;

/**
 * Feature tests for what a subject holds, and where (N93): a principal's own
 * grants and its identity's when they reach it, never a sibling principal's; an
 * identity's and every principal's the directory lists, with completeness;
 * every route through a role and the roles above it, in the review's order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(HoldingRoutes::class)]
final class HoldingRoutesTest extends TestCase
{
    use ActivatesBreakGlass, ReviewsAccess;

    /**
     * A subject holds each role granted, each role above it, what each of them
     * carries, and what it is granted directly, in the review's order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectHoldsEveryRouteOfItsGrants(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        $admin->givePermissionTo(self::permission('posts:delete'));
        $editor->givePermissionTo(self::permission('posts:edit'));
        self::grants()->attachPolicy($admin, self::policy('deny-admin'));

        self::grants()->grantRole($ann, $editor);
        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->attachPolicy($ann, self::policy('deny-own'));

        $result = self::trusted(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere()));

        $rows = self::described($result);

        self::assertSame('role_grant ann [editor] editor', $rows[0]);
        self::assertSame('role_inherited ann [editor>admin] admin', $rows[1]);
        self::assertSame('permission_grant ann posts:read', $rows[2]);
        self::assertEqualsCanonicalizing(['role_permission ann [editor>admin] posts:delete', 'role_permission ann [editor] posts:edit'], [$rows[3], $rows[4]]);
        self::assertSame('policy_attachment ann deny-own', $rows[5]);
        self::assertSame('role_policy ann [editor>admin] deny-admin', $rows[6]);
        self::assertCount(7, $rows);
        self::assertTrue($result->isComplete);
        self::assertSame(SubjectState::ACTIVE, $result->rows[0]->subjectState);
    }

    /**
     * A principal holds what its break-glass activation not ended or expired
     * holds, whether break-glass is enabled or not, as rows of their own beside
     * its grant of the same role, never its identity's activation; an
     * identity's review lists its own and every listed principal's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalHoldsItsOwnActivationsButNeverItsIdentitys(): void
    {
        $admin     = self::role('admin');
        $editor    = self::role('editor', $admin);
        $identity  = self::identity('person');
        $principal = self::identity('person-web');

        $admin->givePermissionTo(self::permission('posts:edit'));
        self::grants()->grantRole($principal, $editor);
        self::grants()->grantRole($identity, $admin);
        self::activate($principal, $editor);
        self::activate($identity, $admin);
        self::activate($principal, $admin, ['expires_at' => Carbon::now()->subSecond()]);
        self::switchBreakGlass(false);

        self::assertSame([
            'role_grant person-web [editor] editor',
            'role_grant person-web [editor] editor (break-glass)',
            'role_grant person-web via person [admin] admin',
            'role_inherited person-web [editor>admin] admin',
            'role_inherited person-web [editor>admin] admin (break-glass)',
            'role_permission person-web [editor>admin] posts:edit',
            'role_permission person-web [editor>admin] posts:edit (break-glass)',
            'role_permission person-web via person [admin] posts:edit',
        ], self::sorted(self::trusted(ReviewQuery::holdings(new Subject($principal, $identity), ReviewScope::everywhere()))));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([ListedIdentityDirectory::key(Reference::of($identity)) => [Reference::of($principal)]]));

        $held = self::described(self::trusted(ReviewQuery::holdings($identity, ReviewScope::everywhere())));

        self::assertContains('role_grant person [admin] admin (break-glass)', $held);
        self::assertContains('role_grant person via person-web [editor] editor (break-glass)', $held);
    }

    /**
     * In principal mode, the identity's grants reach the principal through the
     * identity, while a sibling principal's never do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalHoldsItsIdentitysGrantsButNeverASiblings(): void
    {
        $identity  = self::identity('person');
        $principal = self::identity('person-web');
        $sibling   = self::identity('person-api');

        self::grants()->grantPermission($identity, self::permission('identity:read'));
        self::grants()->grantPermission($principal, self::permission('own:read'));
        self::grants()->grantPermission($sibling, self::permission('sibling:read'));

        $result = self::trusted(ReviewQuery::holdings(new Subject($principal, $identity), ReviewScope::everywhere()));

        self::assertEqualsCanonicalizing(['permission_grant person-web via person identity:read', 'permission_grant person-web own:read'], self::described($result));

        $via = [];

        foreach ($result->rows as $row) {
            $via[$row->grantee->id] = $row->viaIdentity?->id;
        }

        \ksort($via);

        self::assertSame(['person' => 'person', 'person-web' => null], $via);
    }

    /**
     * A person's identity grants never reach a machine principal, nor a
     * machine's a person principal, as a check reads them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOfTheOtherKindGrantsNothing(): void
    {
        $person  = self::identity('person');
        $machine = StubMachine::query()->create(['id' => 'machine']);

        self::grants()->grantPermission($person, self::permission('person:read'));
        self::grants()->grantPermission($machine, self::permission('machine:read'));

        self::assertSame(
            ['permission_grant machine machine:read'],
            self::described(self::trusted(ReviewQuery::holdings(new Subject($machine, $person), ReviewScope::everywhere()))),
        );

        $robot = StubMachine::query()->create(['id' => 'robot']);

        self::grants()->grantPermission($robot, self::permission('robot:read'));

        self::assertEqualsCanonicalizing(
            ['permission_grant machine via robot robot:read', 'permission_grant machine machine:read'],
            self::described(self::trusted(ReviewQuery::holdings(new Subject($machine, $robot), ReviewScope::everywhere()))),
        );
    }

    /**
     * In identity mode, the identity's grants and every listed principal's are
     * read, each row keeping its actual grantee, and the result is complete
     * only when the directory says so.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysHoldingsCoverEveryListedPrincipal(): void
    {
        $identity = self::identity('person');
        $web      = self::identity('person-web');
        $api      = self::identity('person-api');

        self::grants()->grantPermission($identity, self::permission('identity:read'));
        self::grants()->grantPermission($web, self::permission('web:read'));
        self::grants()->grantPermission($api, self::permission('api:read'));

        $key = ListedIdentityDirectory::key(Reference::of($identity));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([$key => [Reference::of($web), Reference::of($api)]]));

        $complete = self::trusted(ReviewQuery::holdings($identity, ReviewScope::everywhere()));

        self::assertEqualsCanonicalizing(
            ['permission_grant person identity:read', 'permission_grant person via person-api api:read', 'permission_grant person via person-web web:read'],
            self::described($complete),
        );
        self::assertTrue($complete->isComplete);

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([$key => [Reference::of($web)]], false));

        $incomplete = self::trusted(ReviewQuery::holdings(Reference::of($identity), ReviewScope::everywhere()));

        self::assertEqualsCanonicalizing(['permission_grant person identity:read', 'permission_grant person via person-web web:read'], self::described($incomplete));
        self::assertFalse($incomplete->isComplete);
    }

    /**
     * An identity with more principals than one query of grants takes has them
     * read a chunk at a time, so no query's bindings grow with them, and every
     * principal's grants are still listed, in the review's order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysPrincipalsAreReadAChunkAtATime(): void
    {
        $identity   = self::identity('person');
        $principals = [];

        for ($index = 0; $index <= GrantRows::CHUNK * 2; $index++) {
            $principals[] = new Reference('principal', \sprintf('p%04d', $index));
        }

        $last = $principals[\count($principals) - 1];

        $permission = self::permission('posts:read');

        foreach ([$identity, $last, $principals[GrantRows::CHUNK], $principals[0]] as $grantee) {
            self::grants()->grantPermission($grantee, $permission);
        }

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([ListedIdentityDirectory::key(Reference::of($identity)) => \array_reverse($principals)]));

        $bindings = [];

        DB::listen(static function (QueryExecuted $executed) use (&$bindings): void {
            $bindings[] = \count($executed->bindings);
        });

        $result = self::trusted(ReviewQuery::holdings($identity, ReviewScope::everywhere()));

        $this->app?->make('events')->forget(QueryExecuted::class);

        self::assertNotEmpty($bindings);
        self::assertLessThanOrEqual(GrantRows::CHUNK + 16, \max($bindings));
        self::assertSame(
            [
                'permission_grant person posts:read',
                'permission_grant person via p0000 posts:read',
                'permission_grant person via p0500 posts:read',
                'permission_grant person via p1000 posts:read',
            ],
            self::described($result),
        );
    }

    /**
     * An inactive subject keeps its live grants, marked inactive, and so does
     * an active principal whose identity is inactive.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveSubjectKeepsItsGrants(): void
    {
        $subject = SuspendableIdentity::query()->create(['id' => 'suspended']);

        self::grants()->grantPermission($subject, self::permission('posts:read'));

        $subject->suspended = true;

        $result = self::trusted(ReviewQuery::holdings(new Subject($subject, $subject), ReviewScope::everywhere()));

        self::assertCount(1, $result->rows);
        self::assertSame(SubjectState::INACTIVE, $result->rows[0]->subjectState);

        $principal = self::identity('principal');

        self::grants()->grantPermission($principal, self::permission('principal:read'));

        $inactive = self::trusted(ReviewQuery::holdings(new Subject($principal, $subject), ReviewScope::everywhere()));

        self::assertCount(2, $inactive->rows);
        self::assertSame([SubjectState::INACTIVE, SubjectState::INACTIVE], [$inactive->rows[0]->subjectState, $inactive->rows[1]->subjectState]);
        self::assertSame(SubjectState::ACTIVE, self::trusted(ReviewQuery::holdings(new Subject($principal, $principal), ReviewScope::everywhere()))->rows[0]->subjectState);
    }

    /**
     * In a review of what applies in a tenant, only the grants that apply there
     * are held: the platform's, the tenant's own, and an ancestor's that
     * reaches below it, never a child's or a sibling's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHoldingsApplyInTheReviewedTenant(): void
    {
        $this->tree();

        $ann = self::identity('ann');

        $tenants = ['platform' => null, 'org1' => self::tenant('org1'), 'acct1' => self::tenant('acct1'), 'team1' => self::tenant('team1'), 'acct2' => self::tenant('acct2')];

        foreach ($tenants as $name => $tenant) {
            self::grants()->grantPermission($ann, self::permission($name . ':read'), tenant: $tenant);
        }

        self::grants()->grantPermission($ann, self::permission('org1-node:read'), tenant: self::tenant('org1'), includeSubtree: false);

        $rows = self::described(self::trusted(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()))));

        self::assertEqualsCanonicalizing(['permission_grant ann platform:read', 'permission_grant ann org1:read', 'permission_grant ann acct1:read'], $rows);

        $rooted = self::described(self::trusted(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::rootedWithin(self::tenant('acct1')))));

        self::assertEqualsCanonicalizing(['permission_grant ann acct1:read', 'permission_grant ann team1:read'], $rooted);
    }

    /**
     * A review filtered by an action keeps only the routes whose permission or
     * policy gives it, each with what gives it, before the rows are cut to the
     * limit; an unfiltered review keeps every route, none with evidence.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReviewFilteredByAnActionKeepsOnlyTheRoutesGivingIt(): void
    {
        $editor = self::role('editor');
        $ann    = self::identity('ann');

        $editor->givePermissionTo(self::permission('posts:*'));

        self::grants()->grantRole($ann, $editor);
        self::grants()->grantPermission($ann, self::permission('comments:read'));
        self::grants()->grantPermission($ann, self::permission('posts:edit'));

        $query    = ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere());
        $filtered = self::trusted($query->forAction('posts:edit')->withLimit(1));
        $all      = self::trusted($query);

        self::assertSame(['permission_grant ann posts:edit'], self::described($filtered));
        self::assertTrue($filtered->isTruncated);
        self::assertSame('posts:edit', $filtered->rows[0]->evidence?->action);
        self::assertCount(2, self::trusted($query->forAction('posts:edit'))->rows);
        self::assertCount(4, $all->rows);
        self::assertSame([null, null, null, null], \array_map(static fn (ReviewRow $row): mixed => $row->evidence, $all->rows));
    }

    /**
     * A subject whose principal is neither a model nor a reference has no
     * holdings to review.
     *
     * @return void
     */
    public function testASubjectWithoutAModelPrincipalIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        ReviewQuery::holdings(new Subject(new \stdClass, null), ReviewScope::everywhere());
    }

    /**
     * Describe the rows of the result, sorted, so the routes compare whatever
     * the roles' keys.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResult  $result
     * @return list<string>
     */
    private static function sorted(ReviewResult $result): array
    {
        $rows = self::described($result);

        \sort($rows);

        return $rows;
    }
}
