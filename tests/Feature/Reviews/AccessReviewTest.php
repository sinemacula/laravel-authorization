<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\Reviews\NamedInactiveIdentity;
use Tests\TestCase;

/**
 * Feature tests for the access review service (AUTHZ-11.6): a review run as a
 * reviewer once admitted, or as trusted work; its rows bounded by a limit with
 * an exact truncation flag, in one total order the same on every database,
 * naming references alone, read on the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AccessReview::class)]
final class AccessReviewTest extends TestCase
{
    use PreviewsSubjects, ReviewsAccess, UsesAnAuthorizationConnection {
        ReviewsAccess::permission insteadof PreviewsSubjects;
    }

    /**
     * A trusted review runs with no reviewer; a review as a reviewer runs once
     * admitted, and returns the same rows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedReviewAndAnAdmittedOneReturnTheSameRows(): void
    {
        $role = self::role('reviewed');

        self::grants()->grantRole(self::identity('ann'), $role);

        $reviewer = StubIdentity::query()->create(['id' => 'reviewer']);

        self::grants()->grantPermission($reviewer, self::permission(PackagePermissions::REVIEW_READ));

        $this->signIn($reviewer);

        $query    = ReviewQuery::holders($role, ReviewScope::everywhere());
        $trusted  = self::trusted($query);
        $admitted = self::reviews()->review($query, ActingContext::current());

        self::assertSame($trusted->toArray()[0]['row_key'], $admitted->toArray()[0]['row_key']);
        self::assertSame(['role_grant ann [reviewed] reviewed'], self::described($admitted));
        self::assertTrue($admitted->isComplete);
    }

    /**
     * A reviewer that cannot be resolved is refused, never treated as trusted.
     *
     * @return void
     */
    public function testAnUnresolvedReviewerIsNeverTrusted(): void
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(null));
        $this->app?->forgetInstance(ResolvedTenant::class);

        try {
            self::reviews()->review(ReviewQuery::holders(self::role('reviewed'), ReviewScope::everywhere()), ActingContext::current());
            self::fail('An unresolved reviewer was admitted.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $exception->getReason());
        }
    }

    /**
     * The limit bounds the rows, and the truncation flag is exact: false when
     * the rows are exactly the limit, true only when one is left out. The
     * default limit is the configured one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitBoundsTheRowsAndTruncationIsExact(): void
    {
        $role = self::role('reviewed');

        foreach (['a', 'b', 'c'] as $id) {
            self::grants()->grantRole(self::identity($id), $role);
        }

        $query = ReviewQuery::holders($role, ReviewScope::everywhere());

        $exact = self::trusted($query->withLimit(3));

        self::assertCount(3, $exact->rows);
        self::assertFalse($exact->isTruncated);

        $short = self::trusted($query->withLimit(2));

        self::assertSame(['a', 'b'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $short->rows));
        self::assertTrue($short->isTruncated);

        config(['authorization.reviews.limit' => 1]);

        self::assertTrue(self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->isTruncated);
    }

    /**
     * The order is total and byte for byte, the same on every database:
     * grantees with keys differing only in case, a trailing space, accents or
     * symbols come in `strcmp()` order, and for one grantee the platform comes
     * before a tenant, and every application before a named one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOrderIsTotalAndTheSameOnEveryDatabase(): void
    {
        $role = self::role('reviewed');
        $keys = ['b', 'B', 'a ', 'a', "\u{e4}", "\u{1f600}", 'a\'b', '10', '9', 'a%_'];

        foreach ($keys as $key) {
            self::grants()->grantRole(new Reference('odd type', $key), $role);
        }

        $tenant = new Reference('tenant', 'T');

        self::grants()->grantRole(new Reference('odd type', 'z'), $role, tenant: $tenant, application: 'web');
        self::grants()->grantRole(new Reference('odd type', 'z'), $role, tenant: $tenant);
        self::grants()->grantRole(new Reference('odd type', 'z'), $role, application: 'web');
        self::grants()->grantRole(new Reference('odd type', 'z'), $role);

        $rows = self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->rows;

        $sorted = [...$keys, 'z', 'z', 'z', 'z'];

        \usort($sorted, static fn (string $one, string $other): int => \strcmp($one, $other));

        self::assertSame($sorted, \array_map(static fn (ReviewRow $row): string => $row->grantee->id, $rows));

        $last = \array_values(\array_filter($rows, static fn (ReviewRow $row): bool => $row->grantee->id === 'z'));

        $scopes = \array_map(static fn (ReviewRow $row): string => ($row->originScope->tenantId ?? '-') . '/' . ($row->originScope->application ?? '-'), $last);

        self::assertSame(['-/-', '-/web', 'T/-', 'T/web'], $scopes);
        self::assertSame(SubjectState::UNKNOWN, $rows[0]->subjectState);
    }

    /**
     * A grant naming half a tenant is listed exactly where a check reads it, a
     * key without a type at the platform and so in every tenant, a type without
     * a key nowhere; both are listed in a review of everywhere and neither in
     * one rooted within a tenant, by holders, holdings, expiries and an actor's
     * grants alike, each marked malformed, its origin scope as stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantNamingHalfATenantIsListedWhereACheckReadsIt(): void
    {
        $this->tree();

        $role   = self::role('reviewed');
        $ann    = self::identity('ann');
        $at     = now('UTC')->addMonth()->startOfSecond();
        $writer = new Reference('user', 'writer');

        self::grants()->grantRole($ann, $role, $at, tenant: self::tenant('acct1'));
        self::grants()->grantRole($ann, $role, $at, tenant: self::tenant('acct2'));

        DB::table('authorizable_roles')->where('tenant_id', 'acct1')->update(['tenant_type' => null, 'granted_by_type' => $writer->type, 'granted_by_id' => $writer->id]);
        DB::table('authorizable_roles')->where('tenant_id', 'acct2')->update(['tenant_id' => null, 'granted_by_type' => $writer->type, 'granted_by_id' => $writer->id]);

        $noType = ['type' => null, 'id' => 'acct1'];
        $noKey  = ['type' => 'tenant', 'id' => null];

        $expected = [
            [ReviewScope::everywhere(), [$noType, $noKey]],
            [ReviewScope::appliesIn(null, ApplicationSelector::none()), [$noType]],
            [ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()), [$noType]],
            [ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::any()), [$noType]],
            [ReviewScope::rootedWithin(self::tenant('org1')), []],
            [ReviewScope::rootedWithin(self::tenant('acct1')), []],
            [ReviewScope::rootedWithin(self::tenant('acct2')), []],
        ];

        foreach ($expected as [$scope, $tenants]) {
            $queries = [
                'holders'    => ReviewQuery::holders($role, $scope),
                'holdings'   => ReviewQuery::holdings(new Subject($ann, $ann), $scope),
                'expiring'   => ReviewQuery::expiring($scope, $at->copy()->subDay(), $at->copy()->addDay()),
                'granted_by' => ReviewQuery::grantedBy($writer, $scope),
            ];

            foreach ($queries as $kind => $query) {
                $rows = self::trusted($query)->rows;

                self::assertSame(
                    \array_map(static fn (array $tenant): array => [$tenant, 'malformed'], $tenants),
                    \array_map(static fn (ReviewRow $row): array => [$row->toArray()['origin_scope']['tenant'] ?? null, $row->toArray()['grant_state']], $rows),
                    "{$kind} in " . $scope->selection->value,
                );
            }
        }
    }

    /**
     * A route resting on a role's policy attachment naming half a tenant is
     * marked malformed, its supporting row as stored: one with a key and no
     * type reaches a holder anywhere, as a check reads it at the platform; one
     * with a type and no key reaches only a holder of a platform-wide grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARouteThroughAnAttachmentNamingHalfATenantIsMalformed(): void
    {
        $this->tree();

        $role    = self::role('carrier');
        $noType  = self::policy('no-type');
        $noKey   = self::policy('no-key');
        $holders = static fn (Policy $policy): array => \array_map(
            static fn (ReviewRow $row): array => [$row->subject->id, $row->grantState->value, $row->toArray()['supporting_grants'][1]['scope']['tenant'] ?? null],
            self::trusted(ReviewQuery::holders($policy, ReviewScope::everywhere()))->rows,
        );

        self::grants()->attachPolicy($role, $noType, tenant: self::tenant('acct1'), includeSubtree: false);
        self::grants()->attachPolicy($role, $noKey, tenant: self::tenant('acct1'), includeSubtree: false);
        self::grants()->grantRole(self::identity('elsewhere'), $role, tenant: self::tenant('acct2'), includeSubtree: false);
        self::grants()->grantRole(self::identity('platform'), $role);

        DB::table('authorizable_policies')->where('policy_id', $noType->getKey())->update(['tenant_type' => null]);
        DB::table('authorizable_policies')->where('policy_id', $noKey->getKey())->update(['tenant_id' => null]);

        self::assertEqualsCanonicalizing([
            ['elsewhere', 'malformed', ['type' => null, 'id' => 'acct1']],
            ['platform', 'malformed', ['type' => null, 'id' => 'acct1']],
        ], $holders($noType));
        self::assertSame([['platform', 'malformed', ['type' => 'tenant', 'id' => null]]], $holders($noKey));
    }

    /**
     * Rows naming half a tenant take their place in the one order by their
     * tenant columns as stored, each null first, the same for holders read in
     * the database's order as for holdings sorted in PHP, on every database.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsNamingHalfATenantAreOrderedByWhatTheyStore(): void
    {
        $role    = self::role('reviewed');
        $grantee = new Reference('odd type', 'z');

        self::grants()->grantRole($grantee, $role, tenant: new Reference('tenant', 'type-only'));
        self::grants()->grantRole($grantee, $role, tenant: new Reference('tenant', 'key-only'));
        self::grants()->grantRole($grantee, $role, tenant: new Reference('tenant', 'x'));
        self::grants()->grantRole($grantee, $role);

        DB::table('authorizable_roles')->where('tenant_id', 'type-only')->update(['tenant_id' => null]);
        DB::table('authorizable_roles')->where('tenant_id', 'key-only')->update(['tenant_type' => null, 'tenant_id' => 'x']);

        $describe = static fn (array $rows): array => \array_map(
            static fn (ReviewRow $row): string => ($row->originScope->tenantType ?? '-') . '/' . ($row->originScope->tenantId ?? '-') . ' ' . $row->grantState->value,
            $rows,
        );

        $expected = ['-/- live', '-/x malformed', 'tenant/- malformed', 'tenant/x live'];

        self::assertSame($expected, $describe(self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->rows));
        self::assertSame($expected, $describe(self::trusted(ReviewQuery::holdings($grantee, ReviewScope::everywhere()))->rows));
    }

    /**
     * A row names references alone: no name, description, document or other
     * value of a definition or of a subject appears anywhere in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsNameReferencesAlone(): void
    {
        $role = new Role;

        $role->forceFill(['name' => 'SENTINEL-ROLE', 'description' => 'SENTINEL-DESCRIPTION'])->save();

        $permission = new Permission;

        $permission->forceFill(['name' => 'sentinel:permission', 'description' => 'SENTINEL-PERMISSION'])->save();

        $role->givePermissionTo($permission);

        $policy = Policy::query()->create(
            [
                'name'        => 'SENTINEL-POLICY',
                'description' => 'SENTINEL-POLICY-DESCRIPTION',
                'document'    => ['statements' => [['effect' => 'deny', 'actions' => ['sentinel:document']]]],
            ],
        );

        self::grants()->attachPolicy($role, $policy);

        $subject = StubIdentity::query()->create(['id' => 'subject', 'name' => 'SENTINEL-SUBJECT']);

        self::grants()->grantRole($subject, $role);

        $encoded = \json_encode(self::trusted(ReviewQuery::holdings(new Subject($subject, $subject), ReviewScope::everywhere()))->toArray(), \JSON_THROW_ON_ERROR);

        self::assertStringNotContainsStringIgnoringCase('sentinel', $encoded);
        self::assertStringContainsString(Reference::of($role)->id, $encoded);
    }

    /**
     * Each row says what is known of its subject: a holder deleted softly or
     * reporting itself inactive keeps its grants, marked inactive; one that is
     * gone is unknown; any other is active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachRowSaysWhatIsKnownOfItsSubject(): void
    {
        $role    = self::role('reviewed');
        $deleted = NumberedIdentity::query()->create(['name' => 'deleted']);

        self::grants()->grantRole($deleted, $role);
        self::grants()->grantRole(NamedInactiveIdentity::query()->create(['id' => 'inactive', 'name' => 'inactive']), $role);
        self::grants()->grantRole(self::identity('active'), $role);
        self::grants()->grantRole(new Reference((new StubIdentity)->getMorphClass(), 'gone'), $role);

        $deleted->delete();

        $states = [];

        foreach (self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->rows as $row) {
            $states[$row->subject->id] = $row->subjectState;
        }

        self::assertSame(SubjectState::INACTIVE, $states[Reference::of($deleted)->id]);
        self::assertSame(SubjectState::INACTIVE, $states['inactive']);
        self::assertSame(SubjectState::ACTIVE, $states['active']);
        self::assertSame(SubjectState::UNKNOWN, $states['gone']);
    }

    /**
     * Every grant a review reads is read on the write connection, so a replica
     * that lags never hides one.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testTheGrantsAreReadOnTheWriteConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        $permission = self::permission('posts:edit');

        $admin->givePermissionTo($permission);
        self::grants()->attachPolicy($admin, self::policy('deny-delete'));
        self::grants()->grantRole($ann, $editor, now()->addMonth());

        self::authorizationConnection()->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        self::assertCount(4, self::trusted(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::appliesIn(null, ApplicationSelector::none())))->rows);
        self::assertCount(1, self::trusted(ReviewQuery::holders($admin, ReviewScope::everywhere()))->rows);
        self::assertCount(1, self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere()))->rows);
        self::assertCount(1, self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), now()->subYear(), now()->addYear()))->rows);
        self::assertCount(0, self::trusted(ReviewQuery::grantedBy($ann, ReviewScope::everywhere()))->rows);
    }
}
