<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews;

use Carbon\CarbonImmutable;
use Illuminate\Encryption\MissingAppKeyException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException;
use SineMacula\Laravel\Authorization\Exceptions\ReviewExportException;
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
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\Reviews\NamedInactiveIdentity;
use Tests\Fixtures\Reviews\SwitchableSessionPolicySource;
use Tests\TestCase;

/**
 * Feature tests for the access review service (AUTHZ-11.6): a review run as a
 * reviewer once admitted, or as trusted work; its rows bounded by a limit with
 * an exact truncation flag, in one total order the same on every database,
 * naming references alone, read on the write connection; its pages read by
 * signed cursors bound to their review, each admitted again, at an instant
 * frozen for the review, over a live scan; its stream, lazy and admitted for
 * each chunk; and its export as JSON Lines, needing both review rights.
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
    use PreviewsSubjects, RefusesThePackage, ReviewsAccess, UsesAnAuthorizationConnection {
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
     * A grant naming half a tenant is listed exactly where a check reads it,
     * which is nowhere, a key without a type as a type without a key: neither
     * is listed in a review of what applies, at the platform or in a tenant,
     * nor in one rooted within a tenant, and both are listed in a review of
     * everywhere, by holders, holdings, expiries and an actor's grants alike,
     * each marked malformed, its origin scope as stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantNamingHalfATenantIsListedOnlyInAReviewOfEverywhere(): void
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
            [ReviewScope::appliesIn(null, ApplicationSelector::none()), []],
            [ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()), []],
            [ReviewScope::appliesIn(self::tenant('acct2'), ApplicationSelector::none()), []],
            [ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::any()), []],
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
     * type, as one with a type and no key, reaches only a holder of a
     * platform-wide grant, never one holding the role in a tenant, since a
     * check reads neither half anywhere.
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

        self::assertSame([['platform', 'malformed', ['type' => null, 'id' => 'acct1']]], $holders($noType));
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

    /**
     * A page is read by keyset: the first with no cursor, each later one with
     * the cursor the page before returned, at most the limit of rows, until a
     * last page with no cursor; the pages together are the whole review, for a
     * reviewer and as trusted work alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPagesAreReadByCursorUntilTheLast(): void
    {
        self::keyCursors();

        $role  = self::holders(5);
        $query = ReviewQuery::holders($role, ReviewScope::everywhere());

        $this->signIn(self::reviewerWith('reviewer', PackagePermissions::REVIEW_READ));

        $first = self::reviews()->page($query, ActingContext::current(), null, 2);

        self::assertSame(['h0', 'h1'], self::subjectsOf($first->rows));
        self::assertFalse($first->isLast());
        self::assertTrue($first->isComplete);

        $second = self::reviews()->page($query, ActingContext::current(), $first->nextCursor, 2);
        $third  = self::reviews()->page($query, ActingContext::current(), $second->nextCursor, 2);

        self::assertSame(['h2', 'h3'], self::subjectsOf($second->rows));
        self::assertSame(['h4'], self::subjectsOf($third->rows));
        self::assertTrue($third->isLast());
        self::assertSame($first->toArray()[0], self::trusted($query)->toArray()[0]);

        $trusted = self::reviews()->trustedPage($query, null, 3);

        self::assertSame(['h0', 'h1', 'h2'], self::subjectsOf($trusted->rows));
        self::assertSame(['h3', 'h4'], self::subjectsOf(self::reviews()->trustedPage($query, $trusted->nextCursor, 3)->rows));
        self::assertTrue(self::reviews()->trustedPage($query, null, 5)->isLast());
    }

    /**
     * A page reads the query's own limit when none is given, and refuses a
     * limit below one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPageReadsTheQuerysLimitUnlessGivenOne(): void
    {
        self::keyCursors();

        $query = ReviewQuery::holders(self::holders(3), ReviewScope::everywhere())->withLimit(2);

        self::assertSame(['h0', 'h1'], self::subjectsOf(self::reviews()->trustedPage($query)->rows));
        self::assertCount(3, self::reviews()->trustedPage($query, null, 3)->rows);

        $this->expectException(\InvalidArgumentException::class);

        self::reviews()->trustedPage($query, null, 0);
    }

    /**
     * A cursor serves the review it was issued for alone: another query, scope,
     * application selector, reach, window or actor, another reviewer, an
     * impersonated one, or the trusted path where a reviewer was meant, and the
     * reverse, are each refused with the one exception, as is a cursor changed
     * in any part.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACursorServesItsOwnReviewAlone(): void
    {
        self::keyCursors();

        $this->tree();

        $role  = self::holders(3);
        $query = ReviewQuery::holders($role, ReviewScope::everywhere());

        $this->signIn(self::reviewerWith('reviewer', PackagePermissions::REVIEW_READ, PackagePermissions::ADMINISTRATION_IMPERSONATED));

        $cursor  = (string) self::reviews()->page($query, ActingContext::current(), null, 1)->nextCursor;
        $trusted = (string) self::reviews()->trustedPage($query, null, 1)->nextCursor;

        $others = [
            ReviewQuery::holders(self::role('other'), ReviewScope::everywhere()),
            ReviewQuery::holders($role, ReviewScope::everywhere(ApplicationSelector::none())),
            ReviewQuery::holders($role, ReviewScope::rootedWithin(self::tenant('org1'))),
            ReviewQuery::holders($role, ReviewScope::everywhere(), true),
            ReviewQuery::holdings(new Reference('u', 'h0'), ReviewScope::everywhere()),
        ];

        foreach ($others as $other) {
            self::assertCursorRefused(static fn (): mixed => self::reviews()->page($other, ActingContext::current(), $cursor));
        }

        self::assertCursorRefused(static fn (): mixed => self::reviews()->trustedPage($query, $cursor));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current(), $trusted));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current()->impersonatedBy(new Reference('u', 'imp')), $cursor));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current(), $cursor . 'x'));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current(), \strrev($cursor)));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current(), 'not a cursor'));

        $this->signIn(self::reviewerWith('another', PackagePermissions::REVIEW_READ));

        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($query, ActingContext::current(), $cursor));
        $expiring = ReviewQuery::expiring(ReviewScope::everywhere(), now(), now()->addDay());
        $written  = ReviewQuery::grantedBy(new Reference('u', 'a'), ReviewScope::everywhere());

        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($expiring, ActingContext::current(), $cursor));
        self::assertCursorRefused(static fn (): mixed => self::reviews()->page($written, ActingContext::current(), $cursor));
    }

    /**
     * The review's instant is frozen when its first page is read and carried by
     * the cursor: a grant that expires between pages is still listed, and still
     * live, on the later page, and every page reports the same instant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReviewsInstantIsFrozenAcrossItsPages(): void
    {
        self::keyCursors();

        $start = CarbonImmutable::parse('2026-11-08 12:00:00.250000', 'UTC');

        Carbon::setTestNow($start);

        $role = self::role('reviewed');

        foreach (['a', 'b', 'c'] as $id) {
            self::grants()->grantRole(new Reference('u', $id), $role, $start->addMinutes(10));
        }

        $holders  = ReviewQuery::holders($role, ReviewScope::everywhere());
        $expiring = ReviewQuery::expiring(ReviewScope::everywhere(), $start, $start->addHour());

        $first      = self::reviews()->trustedPage($holders, null, 1);
        $firstStale = self::reviews()->trustedPage($expiring, null, 1);

        Carbon::setTestNow($start->addHour());

        $later = self::reviews()->trustedPage($holders, $first->nextCursor, 5);
        $stale = self::reviews()->trustedPage($expiring, $firstStale->nextCursor, 5);

        self::assertSame(['b', 'c'], self::subjectsOf($later->rows));
        self::assertSame(['live', 'live'], \array_map(static fn (ReviewRow $row): string => $row->grantState->value, $stale->rows));
        self::assertSame($start->format('Y-m-d H:i:s.u'), $later->reviewedAt->format('Y-m-d H:i:s.u'));
        self::assertSame([], self::trusted($holders)->rows);
        self::assertSame(['expired', 'expired', 'expired'], \array_map(static fn (ReviewRow $row): string => $row->grantState->value, self::trusted($expiring)->rows));

        Carbon::setTestNow();
    }

    /**
     * Every page is admitted again before anything is read, its cursor
     * included: a right revoked between pages refuses the next page, a tampered
     * cursor never reaching the cursor's check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARightRevokedBetweenPagesRefusesTheNext(): void
    {
        self::keyCursors();

        $query    = ReviewQuery::holders(self::holders(3), ReviewScope::everywhere());
        $reviewer = self::reviewerWith('reviewer', PackagePermissions::REVIEW_READ);

        $this->signIn($reviewer);

        $first = self::reviews()->page($query, ActingContext::current(), null, 1);

        self::grants()->revokePermission($reviewer, PackagePermissions::REVIEW_READ);

        foreach ([$first->nextCursor, 'tampered'] as $cursor) {
            try {
                self::reviews()->page($query, ActingContext::current(), $cursor, 1);
                self::fail('A page was read after the right was revoked.');
            } catch (AuthorizationException $exception) {
                self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
            }
        }
    }

    /**
     * The scan is live: a row written before where the last page ended is never
     * returned, one written after it is, a row revoked before it is read is
     * not, and every row present throughout is returned exactly once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsWrittenOrRevokedBetweenPagesFollowTheLiveScan(): void
    {
        self::keyCursors();

        $role  = self::holders(5);
        $query = ReviewQuery::holders($role, ReviewScope::everywhere());
        $first = self::reviews()->trustedPage($query, null, 2);

        self::grants()->grantRole(new Reference('u', 'h00'), $role);
        self::grants()->grantRole(new Reference('u', 'h9'), $role);
        self::grants()->revokeRole(new Reference('u', 'h3'), $role);

        $read   = self::subjectsOf($first->rows);
        $cursor = $first->nextCursor;

        while ($cursor !== null) {
            $page   = self::reviews()->trustedPage($query, $cursor, 2);
            $cursor = $page->nextCursor;

            \array_push($read, ...self::subjectsOf($page->rows));
        }

        self::assertSame(['h0', 'h1', 'h2', 'h4', 'h9'], $read);
    }

    /**
     * A stream is lazy: nothing is read or decided until it is iterated; then
     * each chunk is read after the reviewer is admitted again, so a right
     * revoked part way refuses the next chunk.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStreamIsLazyAndAdmittedForEachChunk(): void
    {
        $query    = ReviewQuery::holders(self::holders(5), ReviewScope::everywhere());
        $reviewer = self::reviewerWith('reviewer', PackagePermissions::REVIEW_READ);

        $this->signIn($reviewer);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $rows = self::reviews()->stream($query, ActingContext::current(), 2);

        self::assertSame(0, $queries);
        self::assertSame(['h0', 'h1', 'h2', 'h3', 'h4'], self::subjectsOf([...self::reviews()->stream($query, ActingContext::current(), 2)]));

        $read = [];

        try {
            foreach ($rows as $row) {
                $read[] = $row->subject->id;

                if (\count($read) !== 2) {
                    continue;
                }

                self::grants()->revokePermission($reviewer, PackagePermissions::REVIEW_READ);
            }

            self::fail('A chunk was read after the right was revoked.');
        } catch (AuthorizationException) {
            self::assertSame(['h0', 'h1'], $read);
        }

        self::assertSame(['h0', 'h1', 'h2', 'h3', 'h4'], self::subjectsOf([...self::reviews()->trustedStream($query, 1)]));

        $this->expectException(\InvalidArgumentException::class);

        self::reviews()->trustedStream($query, 0);
    }

    /**
     * An export is JSON Lines: a header, one line a row, and a footer, each
     * exactly so, to a stream resource or a callback, the same bytes for each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExportIsAHeaderItsRowsAndAFooter(): void
    {
        Carbon::setTestNow(CarbonImmutable::parse('2026-11-08 12:00:00.5', 'UTC'));

        $query  = ReviewQuery::holders(self::holders(3), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::named('admin/web')));
        $stream = \fopen('php://memory', 'w+b');

        self::assertIsResource($stream);
        self::assertSame(3, self::reviews()->trustedExport($query, $stream, 2));

        \rewind($stream);

        $written = (string) \stream_get_contents($stream);
        $lines   = \explode("\n", $written);

        self::assertSame('', \array_pop($lines));
        self::assertCount(5, $lines);
        self::assertSame(
            '{"record":"header","version":1,"query":"holders","scope":{"selection":"applies_in","tenant":{"type":"tenant","id":"acct1"},'
                . '"application":{"selection":"named","name":"admin/web"}},"reviewed_at":"2026-11-08T12:00:00.500000Z",'
                . '"scan_started_at":"2026-11-08T12:00:00.500000Z","consistency":"live"}',
            $lines[0],
        );
        self::assertSame('{"record":"footer","version":1,"rows":3,"scan_ended_at":"2026-11-08T12:00:00.500000Z","complete":true}', $lines[4]);

        $rows = self::trusted($query)->toArray();

        foreach ([1, 2, 3] as $index) {
            self::assertSame(['record' => 'row', ...$rows[$index - 1]], \json_decode($lines[$index], true, 512, \JSON_THROW_ON_ERROR));
        }

        $called = '';

        self::reviews()->trustedExport($query, static function (string $line) use (&$called): void {
            $called .= $line;
        });

        self::assertSame($written, $called);

        Carbon::setTestNow();
    }

    /**
     * An export needs the export right beside the read right, decided together
     * before anything is written: either alone is refused, and the sink is
     * given nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExportNeedsTheExportRightBesideRead(): void
    {
        $query = ReviewQuery::holders(self::holders(2), ReviewScope::everywhere());

        foreach ([[PackagePermissions::REVIEW_READ], [PackagePermissions::REVIEW_EXPORT]] as $index => $rights) {
            $this->signIn(self::reviewerWith('partial-' . $index, ...$rights));

            $lines = [];

            try {
                self::reviews()->export($query, ActingContext::current(), static function (string $line) use (&$lines): void {
                    $lines[] = $line;
                });
                self::fail('An export was admitted with one right.');
            } catch (AuthorizationException) {
                self::assertSame([], $lines);
            }
        }

        $this->signIn(self::reviewerWith('both', PackagePermissions::REVIEW_READ, PackagePermissions::REVIEW_EXPORT));

        $lines = [];

        self::assertSame(2, self::reviews()->export($query, ActingContext::current(), static function (string $line) use (&$lines): void {
            $lines[] = $line;
        }));
        self::assertCount(4, $lines);
    }

    /**
     * An export is deterministic, the same bytes for the same rows at the same
     * instant, and names references alone: no name, description, document or
     * other value appears in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExportIsDeterministicAndNamesReferencesAlone(): void
    {
        Carbon::setTestNow(CarbonImmutable::parse('2026-11-08 12:00:00', 'UTC'));

        $role = new Role;

        $role->forceFill(['name' => 'SENTINEL-ROLE', 'description' => 'SENTINEL-DESCRIPTION'])->save();

        $permission = new Permission;

        $permission->forceFill(['name' => 'sentinel:permission', 'description' => 'SENTINEL-PERMISSION'])->save();

        $role->givePermissionTo($permission);

        $policy = Policy::query()->create(['name' => 'SENTINEL-POLICY', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['sentinel:document']]]]]);

        self::grants()->attachPolicy($role, $policy);

        $subject = StubIdentity::query()->create(['id' => 'subject', 'name' => 'SENTINEL-SUBJECT sentinel@example.com']);

        self::grants()->grantRole($subject, $role, now()->addMonth());

        $exports = [];

        foreach ([1, 2] as $run) {
            $stream = \fopen('php://memory', 'w+b');

            self::assertIsResource($stream);

            self::reviews()->trustedExport(ReviewQuery::holdings(new Subject($subject, $subject), ReviewScope::everywhere()), $stream, 1);

            \rewind($stream);

            $exports[$run] = (string) \stream_get_contents($stream);
        }

        self::assertSame($exports[1], $exports[2]);
        self::assertStringNotContainsStringIgnoringCase('sentinel', $exports[1]);
        self::assertStringNotContainsString('example.com', $exports[1]);
        self::assertStringContainsString(Reference::of($role)->id, $exports[1]);

        Carbon::setTestNow();
    }

    /**
     * An export is admitted again before every chunk: a step-up that stops
     * being met, or a session cap that no longer covers the right, part way,
     * refuses the next chunk, so the export ends with no footer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpOrCapPartWayRefusesTheRestOfAnExport(): void
    {
        $start = CarbonImmutable::parse('2026-11-08 12:00:00', 'UTC');
        $query = ReviewQuery::holders(self::holders(4), ReviewScope::everywhere());

        Carbon::setTestNow($start);

        $stepped = StubIdentity::query()->create(['id' => 'stepped']);

        self::attachStatements($stepped, 'stepped-up-export', [self::requiring(PackagePermissions::REVIEW_READ), self::requiring(PackagePermissions::REVIEW_EXPORT)]);

        $this->signIn($stepped, 'session-1', null, null, new StubRequirementChecker(RequirementResult::met($start->addMinute()->toDateTimeImmutable())));

        self::assertExportStopsAfterTheFirstChunk($query, static function () use ($start): void {
            Carbon::setTestNow($start->addHour());
        }, DecisionReason::INSUFFICIENT_AUTHENTICATION);

        Carbon::setTestNow();

        $source = new SwitchableSessionPolicySource(['authorization:review.*']);

        $this->app?->instance(SessionPolicySource::class, $source);
        $this->signIn(self::reviewerWith('capped', PackagePermissions::REVIEW_READ, PackagePermissions::REVIEW_EXPORT));

        self::assertExportStopsAfterTheFirstChunk($query, static function () use ($source): void {
            $source->scopes = ['posts:*'];
        }, DecisionReason::SESSION_POLICY);
    }

    /**
     * An export of an identity's holdings says in its footer, as each page
     * does, when the directory could not list every principal; a sink that is
     * neither a stream nor a callback is refused, and a stream that takes
     * nothing fails the export.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExportSaysWhetherItIsCompleteAndRefusesABadSink(): void
    {
        self::keyCursors();

        $identity = self::identity('identity');

        self::grants()->grantRole($identity, self::role('one'));
        self::grants()->grantRole($identity, self::role('two'));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([], false));

        $query = ReviewQuery::holdings($identity, ReviewScope::everywhere());
        $last  = '';

        self::reviews()->trustedExport($query, static function (string $line) use (&$last): void {
            $last = $line;
        }, 1);

        self::assertStringEndsWith('"complete":false}' . "\n", $last);
        self::assertFalse(self::reviews()->trustedPage($query, null, 1)->isComplete);

        try {
            self::reviews()->trustedExport($query, \stream_context_create());
            self::fail('A resource that is no stream was used as the sink.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An access review is exported to a writable stream resource or a callback.', $exception->getMessage());
        }

        $readOnly = \fopen('php://memory', 'rb');

        self::assertIsResource($readOnly);

        $this->expectException(ReviewExportException::class);

        self::reviews()->trustedExport($query, $readOnly);
    }

    /**
     * Signing a cursor needs the application key; a review that fits on one
     * page needs none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACursorNeedsTheApplicationKey(): void
    {
        config(['app.key' => '']);

        $query = ReviewQuery::holders(self::holders(2), ReviewScope::everywhere());

        self::assertTrue(self::reviews()->trustedPage($query, null, 2)->isLast());
        self::assertTrue(self::trusted($query->withLimit(1))->isTruncated);

        $this->expectException(MissingAppKeyException::class);

        self::reviews()->trustedPage($query, null, 1);
    }

    /**
     * Once the package refuses, every review refuses by its own guard, before
     * the reviewer is admitted or a row is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryReviewRefusesOnceThePackageRefuses(): void
    {
        $reviewer = ActingContext::for(StubIdentity::create(['id' => 'user-1']));
        $query    = ReviewQuery::holders(self::role('reviewed'), ReviewScope::everywhere());
        $review   = $this->container()->make(AccessReview::class);
        $sink     = static fn (): null => null;

        $this->refuseThePackage();

        $this->assertEachRefused([
            'review'        => static fn () => $review->review($query, $reviewer),
            'trusted'       => static fn () => $review->trusted($query),
            'page'          => static fn () => $review->page($query, $reviewer),
            'trustedPage'   => static fn () => $review->trustedPage($query),
            'stream'        => static fn () => $review->stream($query, $reviewer),
            'trustedStream' => static fn () => $review->trustedStream($query),
            'export'        => static fn () => $review->export($query, $reviewer, $sink),
            'trustedExport' => static fn () => $review->trustedExport($query, $sink),
        ]);
    }

    /**
     * Return a new role held by the number of grantees given, `h0` and on, in
     * the order a review lists them.
     *
     * @param  int  $count
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private static function holders(int $count): Role
    {
        $role = self::role('reviewed');

        for ($index = 0; $index < $count; $index++) {
            self::grants()->grantRole(new Reference('u', 'h' . $index), $role);
        }

        return $role;
    }

    /**
     * Return a new reviewer granted the rights, platform-wide.
     *
     * @param  string  $id
     * @param  string  ...$rights
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function reviewerWith(string $id, string ...$rights): StubIdentity
    {
        $reviewer = StubIdentity::query()->create(['id' => $id]);

        foreach ($rights as $right) {
            self::grants()->grantPermission($reviewer, Permission::query()->firstOrCreate(['name' => $right]));
        }

        return $reviewer;
    }

    /**
     * Return the subjects' keys of the rows, in their order.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @return list<string>
     */
    private static function subjectsOf(array $rows): array
    {
        return \array_map(static fn (ReviewRow $row): string => $row->subject->id, $rows);
    }

    /**
     * Assert the callback is refused for its cursor, with the one message.
     *
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private static function assertCursorRefused(\Closure $callback): void
    {
        try {
            $callback();
            self::fail('A cursor was read for a review it was not issued for.');
        } catch (InvalidReviewCursorException $exception) {
            self::assertSame('The access review cursor is not valid for this review.', $exception->getMessage());
        }
    }

    /**
     * Assert an export of the query as the reviewer signed in, a chunk of two
     * rows at a time, writes its header and first chunk, then, once the change
     * is made, is refused for the reason before another line.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \Closure(): void  $change
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertExportStopsAfterTheFirstChunk(ReviewQuery $query, \Closure $change, DecisionReason $reason): void
    {
        /** @var \ArrayObject<int, string> $records */
        $records = new \ArrayObject;

        try {
            self::reviews()->export($query, ActingContext::current(), static function (string $line) use ($records, $change): void {
                /** @var array{record: string} $record */
                $record = \json_decode($line, true, 512, \JSON_THROW_ON_ERROR);

                $records->append($record['record']);

                if (\count($records) !== 3) {
                    return;
                }

                $change();
            }, 2);
            self::fail('An export ran on after the reviewer stopped being admitted.');
        } catch (AuthorizationException $exception) {
            self::assertSame($reason, $exception->getReason());
            self::assertSame(['header', 'row', 'row'], $records->getArrayCopy());
        }
    }
}
