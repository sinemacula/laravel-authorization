<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BreakGlassService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\RacesDelegatedCalls;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ReportsEveryDecision;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Concerns\WidensGrants;
use Tests\Feature\Stubs\ApiGuardedUser;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for `BreakGlassService`, which activates, surrenders and
 * revokes break-glass activations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BreakGlassService::class)]
final class BreakGlassServiceTest extends TestCase
{
    use ActivatesBreakGlass, ActsAsAdministrator, CatchesRefusals, RacesDelegatedCalls, RecordsRowLocks, RefusesThePackage, ReportsEveryDecision, UsesAnAuthorizationConnection,
        WidensGrants;

    /** @var string The action the emergency role carries. */
    private const string ACTION = 'posts:create';

    /**
     * Start the clock, put the tenants in the tree and switch break-glass on:
     * `responder` for at most 30 minutes, `auditor` for the global 60, two
     * codes, and notes of at most four characters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');

        $this->closureTree();

        self::switchBreakGlass(true, [
            'max_minutes'     => 60,
            'roles'           => ['responder' => ['max_minutes' => 30], 'auditor' => []],
            'justifications'  => ['incident', 'audit'],
            'notes'           => true,
            'note_max_length' => 4,
        ]);
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A trusted activation is a record of its own, live from now for exactly
     * the minutes given, in UTC, naming no granter, its scope, its code and its
     * note; the role is then granted in the tenant and below it alone, beside a
     * normal grant of another role.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedActivationGrantsTheRoleInItsScopeAlone(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole(self::ACTION);

        self::assertFalse($user->hasRole('responder'));

        $activation = self::service()->activate($user, 'responder', new GrantScope(self::tenant('acct1'), null), 30, 'incident', 'Page');
        $stored     = BreakGlassActivation::query()->findOrFail($activation->id);

        self::assertSame(
            [Reference::of($role)->id, $user->getMorphClass(), 'user-1', null, null, 'tenant', 'acct1', true, null, 'incident', 'Page', null],
            [
                $stored->role_id, $stored->authorizable_type, $stored->authorizable_id, $stored->granted_by_type, $stored->granted_by_id, $stored->tenant_type,
                $stored->tenant_id, $stored->include_subtree, $stored->application, $stored->justification, $stored->note, $stored->ended_at,
            ],
        );
        self::assertSame('2026-07-01 12:00:00', $stored->activated_at->toDateTimeString());
        self::assertSame('2026-07-01 12:30:00', $stored->expires_at->toDateTimeString());
        self::assertSame('UTC', $stored->expires_at->getTimezone()->getName());
        self::assertTrue(BreakGlassActivations::isCounted($user));

        $allowed = \array_map(static fn (?string $tenant): bool => self::allows($user, $tenant), [null, 'org1', 'acct1', 'team1', 'acct2', 'org2']);

        self::assertSame([false, false, true, true, false, false], $allowed);

        Carbon::setTestNow('2026-07-01 12:30:00');

        self::assertFalse(self::allows(StubIdentity::query()->findOrFail('user-1'), 'acct1'));
    }

    /**
     * A platform-wide activation reaches every tenant, whatever its reach says,
     * an application limits it to that application, and the grantee's loaded
     * roles are read again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformActivationReachesEveryTenantOfItsApplication(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole(self::ACTION);

        $user->load('roles');

        $activation = self::service()->activate($user, $role, new GrantScope(null, 'admin', false), 5, 'audit');

        self::assertTrue($activation->include_subtree);
        self::assertSame('admin', $activation->application);
        self::assertSame('2026-07-01 12:05:00', $activation->expires_at->toDateTimeString());
        self::assertFalse($user->relationLoaded('roles'));
        self::assertTrue(AuthorizationScope::tenant(self::tenant('team1'), 'admin')->within(static fn (): bool => Authorization::for($user)->can(self::ACTION)));
        self::assertFalse(AuthorizationScope::tenant(self::tenant('team1'), 'web')->within(static fn (): bool => Authorization::for($user)->can(self::ACTION)));
    }

    /**
     * A delegated activation is decided under the right for oneself or the
     * right for another, in the activation's tenant and application, and
     * records the actor as its granter; holding the right is enough, so an
     * unranked actor activates the role for a senior administrator.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedActivationIsDecidedUnderItsRightInItsScope(): void
    {
        $this->reportEveryDecision();

        self::emergencyRole(self::ACTION);

        $self    = self::administrator([PackagePermissions::BREAK_GLASS_ACTIVATE], 'self-1', null);
        $other   = self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'other-1', null);
        $senior  = self::administrator(['authorization:*'], 'senior-1');
        $scope   = new GrantScope(self::tenant('acct1'), 'admin', false);
        $decided = self::recordDecisions();

        $own = self::service()->activate(self::principalOf($self), 'responder', $scope, 10, 'incident', actor: $self);

        self::assertSame([PackagePermissions::BREAK_GLASS_ACTIVATE], self::decided($decided));
        self::assertSame([$self->principal()->type, 'self-1'], [$own->granted_by_type, $own->granted_by_id]);

        $decided->exchangeArray([]);

        $for = self::service()->activate(self::principalOf($senior), 'responder', $scope, 10, 'incident', actor: $other);

        self::assertSame([PackagePermissions::BREAK_GLASS_GRANT], self::decided($decided));
        self::assertSame('other-1', $for->granted_by_id);
        self::assertSame(2, BreakGlassActivation::query()->count());

        $renamed       = self::emergencyRole('posts:other', 'unlisted');
        $renamed->name = 'responder';

        $stored = self::refusalOf(static fn () => self::service()->activate(self::principalOf($senior), $renamed, $scope, 10, 'incident', actor: $other));

        self::assertInstanceOf(BreakGlassRefusedException::class, $stored);
        self::assertSame(BreakGlassRefusal::NOT_LISTED, $stored->getReason());

        self::assertInstanceOf(AuthorizationException::class, self::refusalOf(static fn () => self::activateFor(self::principalOf($other), $other, $scope)));
        self::assertInstanceOf(AuthorizationException::class, self::refusalOf(static fn () => self::activateFor(self::principalOf($other), $self, $scope)));
        self::assertSame(2, BreakGlassActivation::query()->count());
    }

    /**
     * A delegated activation locks what a delegated grant of the role locks, in
     * the same order, before it is decided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedActivationLocksWhatARoleGrantLocks(): void
    {
        $this->reportEveryDecision();

        $role  = self::emergencyRole(self::ACTION);
        $actor = self::administrator();
        $first = StubIdentity::query()->create(['id' => 'user-1']);
        $other = StubIdentity::query()->create(['id' => 'user-2']);
        $grant = $this->lockedBeforeDeciding(PackagePermissions::ROLE_GRANT, static fn () => GrantService::instance()?->grantRole($first, $role, actor: $actor));

        $activation = $this->lockedBeforeDeciding(PackagePermissions::BREAK_GLASS_GRANT, static fn () => self::activateFor($other, $actor, role: $role));

        self::assertContains('roles', $activation);
        self::assertContains('authorizable_roles', $activation);
        self::assertSame($grant, $activation);
    }

    /**
     * The rights are decided in the activation's tenant: a right held in a
     * tenant activates there and below, and ends an activation there, but
     * neither elsewhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightsAreDecidedInTheActivationsScope(): void
    {
        $user  = StubIdentity::query()->create(['id' => 'user-1']);
        $actor = self::administrator([], 'admin-1', null);
        $admin = self::principalOf($actor);

        self::emergencyRole(self::ACTION);

        foreach ([PackagePermissions::BREAK_GLASS_GRANT, PackagePermissions::BREAK_GLASS_REVOKE] as $right) {
            GrantService::instance()?->grantPermission($admin, Permission::query()->firstOrCreate(['name' => $right]), tenant: self::tenant('org1'));
        }

        $org      = self::tenant('org1');
        $activate = static fn (string $tenant): BreakGlassActivation => TenantScope::within($org, null, static fn (): BreakGlassActivation => self::service()
            ->activate($user, 'responder', new GrantScope(self::tenant($tenant)), 10, 'incident', actor: $actor));
        $revoke = static fn (BreakGlassActivation $activation): int => TenantScope::within($org, null, static fn (): int => self::service()->revoke($activation, $actor));

        $below = $activate('acct1');

        self::assertInstanceOf(AuthorizationException::class, self::refusalOf(static fn () => $activate('org2')));
        self::assertSame(1, $revoke($below));

        $elsewhere = self::service()->activate($user, 'responder', new GrantScope(self::tenant('org2')), 10, 'incident');

        self::assertInstanceOf(AuthorizationException::class, self::refusalOf(static fn () => $revoke($elsewhere)));
        self::assertSame(2, BreakGlassActivation::query()->count());
    }

    /**
     * Return each limit an activation breaks: the settings in place, if any,
     * the grantee, the role, the minutes, the code, the note and the tenant,
     * with the reason it is refused.
     *
     * @return iterable<string, array{
     *     array<string, mixed>, string, string, int, string, string|null,
     *     \SineMacula\Laravel\Authorization\Support\Reference|null, \SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal
     * }>
     */
    public static function refusals(): iterable
    {
        $listed = ['roles' => ['responder' => []], 'justifications' => ['incident']];

        yield 'disabled' => [['enabled' => false, ...$listed], 'user', 'responder', 10, 'incident', null, null, BreakGlassRefusal::DISABLED];
        yield 'machine' => [[], 'machine', 'responder', 10, 'incident', null, null, BreakGlassRefusal::NOT_HUMAN];
        yield 'identity' => [[], 'identity', 'responder', 10, 'incident', null, null, BreakGlassRefusal::NOT_HUMAN];
        yield 'not listed' => [[], 'user', 'unlisted', 10, 'incident', null, null, BreakGlassRefusal::NOT_LISTED];
        yield 'no minutes' => [[], 'user', 'responder', 0, 'incident', null, null, BreakGlassRefusal::DURATION];
        yield 'over role maximum' => [[], 'user', 'responder', 31, 'incident', null, null, BreakGlassRefusal::DURATION];
        yield 'over the maximum' => [[], 'user', 'auditor', 61, 'incident', null, null, BreakGlassRefusal::DURATION];
        yield 'justification' => [[], 'user', 'responder', 10, 'urgent', null, null, BreakGlassRefusal::JUSTIFICATION];
        yield 'notes off' => [['enabled' => true, ...$listed, 'notes' => false], 'user', 'responder', 10, 'incident', 'Hi', null, BreakGlassRefusal::NOTE_REFUSED];
        yield 'note too long' => [[], 'user', 'responder', 10, 'incident', 'ééééé', null, BreakGlassRefusal::NOTE_TOO_LONG];
        yield 'half tenant' => [[], 'user', 'responder', 10, 'incident', null, new Reference('tenant', ''), BreakGlassRefusal::HALF_TENANT];
        yield 'untyped tenant' => [[], 'user', 'responder', 10, 'incident', null, new Reference('', 'acct1'), BreakGlassRefusal::HALF_TENANT];
    }

    /**
     * Every limit refuses the activation with its own reason, before anything
     * is written.
     *
     * @param  array<string, mixed>  $settings
     * @param  string  $grantee
     * @param  string  $role
     * @param  int  $minutes
     * @param  string  $justification
     * @param  string|null  $note
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('refusals')]
    public function testEveryLimitRefusesWithItsReason(
        array $settings,
        string $grantee,
        string $role,
        int $minutes,
        string $justification,
        ?string $note,
        ?Reference $tenant,
        BreakGlassRefusal $reason,
    ): void {
        self::emergencyRole(self::ACTION);
        self::emergencyRole('posts:audit', 'auditor');
        self::emergencyRole('posts:other', 'unlisted');

        if ($settings !== []) {
            self::switchBreakGlass($settings['enabled'] === true, $settings);
        }

        $model   = self::granteeOf($grantee);
        $refusal = self::refusalOf(static fn () => self::service()->activate($model, $role, new GrantScope($tenant), $minutes, $justification, $note));

        self::assertInstanceOf(BreakGlassRefusedException::class, $refusal);
        self::assertSame($reason, $refusal->getReason());
        self::assertSame(0, BreakGlassActivation::query()->count());
    }

    /**
     * Each limit is reached, not passed: a role's maximum, the global one, and
     * a note as long as allowed, measured in characters.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachLimitIsInclusive(): void
    {
        self::emergencyRole(self::ACTION);
        self::emergencyRole('posts:audit', 'auditor');

        $user = StubIdentity::query()->create(['id' => 'user-1']);

        self::service()->activate($user, 'responder', GrantScope::platform(), 30, 'incident', 'éééé');
        self::service()->activate($user, 'auditor', GrantScope::platform(), 60, 'audit');
        self::service()->activate($user, 'auditor', GrantScope::platform(), 1, 'audit');

        self::assertSame(['12:01', '12:30', '13:00'], self::expiries());
    }

    /**
     * A role that does not exist under the grantee's guard, an unsaved grantee,
     * a role of another guard than the grantee's, and a role activated outside
     * the tenant that owns it are refused as a grant of the role would be.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRoleAndGranteeAreHeldToWhatAGrantIsHeldTo(): void
    {
        $user  = StubIdentity::query()->create(['id' => 'user-1']);
        $owned = Role::query()->withoutGlobalScopes()->create(['name' => 'responder', 'tenant_type' => 'tenant', 'tenant_id' => 'org1']);
        $api   = ApiGuardedUser::query()->create(['id' => 'api-1']);
        $web   = Role::query()->withoutGlobalScopes()->create(['name' => 'responder', 'guard' => 'web']);

        $keyless         = new StubIdentity;
        $keyless->exists = true;

        self::assertInstanceOf(UnknownRoleException::class, self::refusalOf(static fn () => self::activateFor($user, role: 'auditor')));
        self::assertInstanceOf(InvalidGranteeException::class, self::refusalOf(static fn () => self::activateFor(new StubIdentity)));
        self::assertInstanceOf(InvalidGranteeException::class, self::refusalOf(static fn () => self::activateFor($keyless)));
        self::assertInstanceOf(GrantScopeMismatchException::class, self::refusalOf(static fn () => self::activateFor($user, role: $owned)));
        self::assertInstanceOf(GranteeGuardMismatchException::class, self::refusalOf(static fn () => self::activateFor($api, role: $web)));
        self::assertSame(0, BreakGlassActivation::query()->count());

        self::service()->activate($user, $owned, new GrantScope(self::tenant('acct1')), 10, 'incident');

        self::assertSame(1, BreakGlassActivation::query()->count());
    }

    /**
     * The grantee surrenders its own activation, ending it as surrendered by
     * itself; anyone else, or the grantee impersonated, is refused, ending it
     * again changes nothing, and a normal grant of the same role is untouched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGranteeAloneSurrendersItsActivation(): void
    {
        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $other      = StubIdentity::query()->create(['id' => 'user-2']);
        $role       = self::emergencyRole(self::ACTION);
        $activation = self::service()->activate($user, $role, GrantScope::platform(), 10, 'incident');
        $beside     = self::service()->activate($other, $role, GrantScope::platform(), 10, 'incident');

        GrantService::instance()?->grantRole($other, $role);

        $refusal = self::refusalOf(static fn () => self::service()->surrender($activation->id, ActingContext::for($other)));
        $alike   = self::refusalOf(static fn () => self::service()->surrender($activation->id, ActingContext::for(StubSecondIdentity::query()->create(['id' => 'user-1']))));
        $posing  = self::refusalOf(static fn () => self::service()->surrender($activation->id, ActingContext::for($user)->impersonatedBy($other)));

        self::assertInstanceOf(BreakGlassRefusedException::class, $refusal);
        self::assertSame(BreakGlassRefusal::NOT_GRANTEE, $refusal->getReason());
        self::assertInstanceOf(BreakGlassRefusedException::class, $alike);
        self::assertInstanceOf(BreakGlassRefusedException::class, $posing);
        self::assertSame(BreakGlassRefusal::NOT_GRANTEE, $posing->getReason());
        self::assertNull(BreakGlassActivation::query()->findOrFail($activation->id)->ended_at);

        Carbon::setTestNow('2026-07-01 12:04:00');

        self::assertSame(1, self::service()->surrender($activation, ActingContext::for($user)));

        $ended = BreakGlassActivation::query()->findOrFail($activation->id);

        self::assertSame('2026-07-01 12:04:00', $ended->ended_at?->toDateTimeString());
        self::assertSame([$user->getMorphClass(), 'user-1', 'surrendered'], [$ended->ended_by_type, $ended->ended_by_id, $ended->end_reason]);
        self::assertFalse(self::allows(StubIdentity::query()->findOrFail('user-1'), null));
        self::assertSame(0, self::service()->surrender($activation->id, ActingContext::for($user)));
        self::assertSame(1, self::service()->surrender($beside, ActingContext::for($other)));
        self::assertTrue(self::allows(StubIdentity::query()->findOrFail('user-2'), null));
    }

    /**
     * A trusted revocation ends an activation as revoked by no one; a delegated
     * one needs the revoke right in the activation's scope and records the
     * actor; ending one ended or expired changes nothing, a normal grant is
     * untouched, and an unknown key is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationNeedsTheRevokeRightInTheActivationsScope(): void
    {
        $this->reportEveryDecision();

        $user    = StubIdentity::query()->create(['id' => 'user-1']);
        $role    = self::emergencyRole(self::ACTION);
        $scope   = new GrantScope(self::tenant('acct1'), 'admin');
        $first   = self::service()->activate($user, $role, $scope, 10, 'incident');
        $second  = self::service()->activate($user, $role, $scope, 10, 'incident');
        $expired = self::service()->activate($user, $role, $scope, 1, 'incident');
        $none    = self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'none-1', null);
        $holder  = self::administrator([PackagePermissions::BREAK_GLASS_REVOKE], 'holder-1', null);
        $decided = self::recordDecisions();

        self::assertSame(1, self::service()->revoke($first->id));
        self::assertSame([null, null, 'revoked'], self::endedBy($first));
        self::assertSame(0, self::service()->revoke($first));

        $refusal = self::refusalOf(static fn () => self::service()->revoke($second, $none));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertNull(BreakGlassActivation::query()->findOrFail($second->id)->ended_at);
        self::assertSame(1, self::service()->revoke($second->id, $holder));
        self::assertSame([$holder->principal()->type, 'holder-1', 'revoked'], self::endedBy($second));
        self::assertSame([PackagePermissions::BREAK_GLASS_REVOKE], self::decided($decided));

        Carbon::setTestNow('2026-07-01 12:01:00');

        self::assertSame(0, self::service()->revoke($expired, $holder));
        self::assertNull(BreakGlassActivation::query()->findOrFail($expired->id)->ended_at);
        DB::enableQueryLog();

        self::assertInstanceOf(ModelNotFoundException::class, self::refusalOf(static fn () => self::service()->revoke('missing')));
        self::assertSame([], \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'break_glass_activations')));
        self::assertInstanceOf(ModelNotFoundException::class, self::refusalOf(static fn () => self::service()->revoke('00000000-0000-4000-8000-000000000000')));
    }

    /**
     * A surrender, a trusted revocation and a delegated one each lock the
     * activation they end, once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachEndLocksTheActivationOnce(): void
    {
        $user   = StubIdentity::query()->create(['id' => 'user-1']);
        $role   = self::emergencyRole(self::ACTION);
        $holder = self::administrator([PackagePermissions::BREAK_GLASS_REVOKE], 'holder-1', null);
        $locks  = $this->recordRowLocks();
        $ends   = [
            'surrender' => static fn (string $id): int => self::service()->surrender($id, ActingContext::for($user)),
            'trusted'   => static fn (string $id): int => self::service()->revoke($id),
            'delegated' => static fn (string $id): int => self::service()->revoke($id, $holder),
        ];

        foreach ($ends as $name => $end) {
            $id = self::service()->activate($user, $role, GrantScope::platform(), 10, 'incident')->id;

            $locks->exchangeArray([]);

            self::assertSame(1, $end($id), $name);

            $locked = \array_filter($locks->getArrayCopy(), static fn (array $lock): bool => $lock[0] === 'break_glass_activations' && \in_array($id, $lock[1], true));

            self::assertCount(1, $locked, $name);
        }
    }

    /**
     * A delegated activation for another and a delegated revocation that
     * conflict on every try are refused as a conflict, reported under their own
     * right, writing nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedCallConflictingOnEveryTryIsReportedUnderItsRight(): void
    {
        $this->reportEveryDecision();

        config(['authorization.administration.retries' => 1]);

        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $actor      = self::administrator([PackagePermissions::BREAK_GLASS_GRANT, PackagePermissions::BREAK_GLASS_REVOKE], 'admin-1', null);
        $rows       = DB::table('authorizable_permissions')->where('authorizable_id', $actor->principal()->id);
        $touch      = static fn (string $at): \Closure => static fn (): int => (clone $rows)->update(['updated_at' => $at]);
        $role       = self::emergencyRole(self::ACTION);
        $activation = self::activateFor($user, role: $role);

        /** @var \ArrayObject<int, string> $failed */
        $failed = new \ArrayObject;

        Event::listen(AuthorizationFailed::class, static fn (AuthorizationFailed $event) => $failed->append($event->action));

        self::raceWith(PackagePermissions::BREAK_GLASS_GRANT, $touch('2001-01-01 00:00:00'), true);
        self::raceWith(PackagePermissions::BREAK_GLASS_REVOKE, $touch('2002-01-01 00:00:00'), true);

        $granted = self::refusalOf(static fn () => self::activateFor($user, $actor, role: $role));
        $revoked = self::refusalOf(static fn () => self::service()->revoke($activation, $actor));

        self::assertInstanceOf(AuthorizationException::class, $granted);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $granted->getReason());
        self::assertInstanceOf(AuthorizationException::class, $revoked);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $revoked->getReason());
        self::assertSame([PackagePermissions::BREAK_GLASS_GRANT, PackagePermissions::BREAK_GLASS_REVOKE], $failed->getArrayCopy());
        self::assertSame(1, BreakGlassActivation::query()->count());
        self::assertNull(BreakGlassActivation::query()->findOrFail($activation->id)->ended_at);
    }

    /**
     * Ending an activation leaves a normal grant of the same role as it was,
     * and is allowed while break-glass is disabled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEndingLeavesANormalGrantAndWorksWhileDisabled(): void
    {
        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $role       = self::emergencyRole(self::ACTION);
        $activation = self::service()->activate($user, $role, new GrantScope(self::tenant('acct1')), 10, 'incident');

        GrantService::instance()?->grantRole($user, $role, tenant: self::tenant('acct2'));

        self::switchBreakGlass(false);

        self::assertFalse(self::allows($user, 'acct1'));
        self::assertSame(1, self::service()->revoke($activation));
        self::assertTrue(self::allows(StubIdentity::query()->findOrFail('user-1'), 'acct2'));
        self::assertSame(1, DB::table('authorizable_roles')->where('authorizable_id', 'user-1')->count());
    }

    /**
     * The grant hooks are asked about an activation as about a grant of its
     * role in its scope until its expiry, before anything is written, and a
     * hook's refusal refuses it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantHooksAreAskedAndMayRefuse(): void
    {
        [, [$principal]] = $this->principals();

        $role  = self::emergencyRole(self::ACTION);
        $hook  = $this->hook(static fn () => self::assertSame(0, BreakGlassActivation::query()->count()));
        $scope = new GrantScope(self::tenant('acct1'), 'admin', false);

        self::service()->activate($principal, $role, $scope, 20, 'incident');

        self::assertCount(1, $hook->widenings);
        self::assertSame(
            [[PackagePermissions::ROLE_GRANT, Reference::of($role)->id, 'acct1', 'admin', false, '2026-07-01T12:20:00+00:00']],
            \array_map(static fn (ProposedGrant $grant): array => [
                $grant->action, $grant->target->id, $grant->tenant?->id, $grant->application, $grant->includeSubtree, $grant->expiresAt?->format(\DATE_ATOM),
            ], $hook->widenings[0]->changes),
        );

        $refusing = new RefusingGrantHook;

        $this->app?->instance(GrantHook::class, $refusing);

        $acct2 = new GrantScope(self::tenant('acct2'));

        self::assertInstanceOf(GrantRefusedException::class, self::refusalOf(static fn () => self::activateFor($principal, scope: $acct2, role: $role)));
        self::assertSame(1, $refusing->refused);
        self::assertSame(1, BreakGlassActivation::query()->count());
    }

    /**
     * Return a trusted call and a delegated one.
     *
     * @return iterable<string, array{bool}>
     */
    public static function callers(): iterable
    {
        yield 'trusted' => [false];
        yield 'delegated' => [true];
    }

    /**
     * An activation that widened nothing as its hook phase read it, but widens
     * once the evidence it relied on, another principal's grant in the tenant,
     * is revoked before the check after the locks, is tried again with its
     * hook, trusted or delegated, and written once.
     *
     * @param  bool  $isDelegated
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('callers')]
    public function testACoverageRaceIsTriedAgainWithTheHook(bool $isDelegated): void
    {
        $this->useAnAuthorizationConnection();

        $actor = $isDelegated ? self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'admin-1', null) : null;

        [, [$first, $second]] = $this->principals();

        $evidence = Role::query()->create(['name' => 'evidence']);
        $role     = self::emergencyRole(self::ACTION);

        GrantService::instance()?->grantRole($second, $evidence, tenant: self::tenant('acct1'));

        $hook  = $this->hook();
        $raced = self::raceOnQuery('/ as grant_roots\b/', static function () use ($second, $evidence): void {
            GrantChanges::table(GrantTarget::ROLE, Reference::of($second), null, new GrantScope(self::tenant('acct1')))->revoke([GrantChanges::key($evidence)]);
        });

        self::service()->activate($first, $role, new GrantScope(self::tenant('acct1'), null, false), 10, 'incident', actor: $actor);

        self::assertCount(1, $raced);
        self::assertSame([[WideningReason::NEW_TENANT->value]], $hook->reasons());
        self::assertSame(1, self::authorizationConnection()->table('break_glass_activations')->count());
    }

    /**
     * A role deleted while a trusted activation runs, after it was read, is
     * refused when it is locked, nothing written; one deleted after a delegated
     * decision has the activation tried again, and refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationRacingTheRolesDeletionIsRefused(): void
    {
        $this->reportEveryDecision();

        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole(self::ACTION);
        $gone = static fn (): int => DB::table('roles')->where('id', $role->getKey())->delete();

        self::raceOnQuery('/^select \* from roles where/', $gone);

        self::assertInstanceOf(UnknownRoleException::class, self::refusalOf(static fn () => self::service()->activate($user, 'responder', GrantScope::platform(), 10, 'incident')));
        self::assertSame(0, BreakGlassActivation::query()->count());

        $actor  = self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'admin-1', null);
        $second = self::emergencyRole(self::ACTION);

        $decisions = self::raceWith(PackagePermissions::BREAK_GLASS_GRANT, static fn (): int => DB::table('roles')->where('id', $second->getKey())->delete());

        self::assertInstanceOf(UnknownRoleException::class, self::refusalOf(static fn () => self::activateFor($user, $actor)));
        self::assertSame([true], $decisions->getArrayCopy());
        self::assertSame(0, BreakGlassActivation::query()->count());
    }

    /**
     * The actor's right revoked between the decision and the write has the
     * activation tried again, and refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationOfTheRightIsRefusedOnTheRetry(): void
    {
        $this->reportEveryDecision();

        $user  = StubIdentity::query()->create(['id' => 'user-1']);
        $actor = self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'admin-1', null);
        $admin = self::principalOf($actor);

        self::emergencyRole(self::ACTION);

        $revoke    = static fn (): int => GrantService::instance()?->revokePermission($admin, PackagePermissions::BREAK_GLASS_GRANT) ?? 0;
        $decisions = self::raceWith(PackagePermissions::BREAK_GLASS_GRANT, $revoke);

        $refusal = self::refusalOf(static fn () => self::service()->activate($user, 'responder', GrantScope::platform(), 10, 'incident', actor: $actor));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::NO_MATCH, $refusal->getReason());
        self::assertTrue($decisions[0] ?? false);
        self::assertFalse($decisions[\count($decisions) - 1] ?? true);
        self::assertSame(0, BreakGlassActivation::query()->count());
    }

    /**
     * A second activation of the same role, written while a delegated one is
     * decided, has it tried again and made: each is a record of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASecondActivationRacingIsTriedAgainAndBothAreKept(): void
    {
        $this->reportEveryDecision();

        $user  = StubIdentity::query()->create(['id' => 'user-1']);
        $actor = self::administrator([PackagePermissions::BREAK_GLASS_GRANT], 'admin-1', null);

        self::emergencyRole(self::ACTION);

        $decisions = self::raceWith(PackagePermissions::BREAK_GLASS_GRANT, static fn () => self::service()->activate($user, 'responder', GrantScope::platform(), 5, 'incident'));

        self::service()->activate($user, 'responder', GrantScope::platform(), 10, 'incident', actor: $actor);

        self::assertGreaterThan(1, \count($decisions));
        self::assertSame(['12:05', '12:10'], self::expiries());
    }

    /**
     * Every operation refuses once the package refuses, before it reads.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryOperationRefusesOnceThePackageRefuses(): void
    {
        $user    = StubIdentity::query()->create(['id' => 'user-1']);
        $actor   = ActingContext::for($user);
        $service = $this->container()->make(BreakGlassService::class);

        $this->refuseThePackage();

        $this->assertEachRefused([
            'activate'  => static fn () => $service->activate($user, 'responder', GrantScope::platform(), 10, 'incident'),
            'surrender' => static fn () => $service->surrender('key', $actor),
            'revoke'    => static fn () => $service->revoke('key'),
        ]);
    }

    /**
     * The service is bound as a singleton.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertSame(BreakGlassService::instance(), app(BreakGlassService::class));
    }

    /**
     * Return the tables the call locked rows of before the first decision of
     * the action, each once, in the order first locked.
     *
     * @param  string  $action
     * @param  \Closure(): mixed  $call
     * @return list<string>
     */
    private function lockedBeforeDeciding(string $action, \Closure $call): array
    {
        $locks = $this->recordRowLocks();

        /** @var \ArrayObject<int, list<string>> $before */
        $before = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($action, $locks, $before): void {
            if ($event->action !== $action || $before->count() > 0) {
                return;
            }

            $before->append(\array_values(\array_unique(\array_column($locks->getArrayCopy(), 0))));
        });

        $call();

        return $before[0] ?? [];
    }

    /**
     * Activate the role for the grantee in the scope, the platform unless one
     * is given, for ten minutes, as the actor given, or trusted.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $scope
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return \SineMacula\Laravel\Authorization\Models\BreakGlassActivation
     *
     * @throws \Throwable
     */
    private static function activateFor(Model $grantee, ?ActingContext $actor = null, ?GrantScope $scope = null, Role|string $role = 'responder'): BreakGlassActivation
    {
        return self::service()->activate($grantee, $role, $scope ?? GrantScope::platform(), 10, 'incident', actor: $actor);
    }

    /**
     * Return the grantee of the kind: a machine, a person read as another
     * subject's identity, or a person.
     *
     * @param  string  $kind
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function granteeOf(string $kind): Model
    {
        if ($kind === 'machine') {
            return StubMachine::query()->create(['id' => 'machine-1']);
        }

        $user = StubIdentity::query()->create(['id' => 'user-1']);

        if ($kind === 'identity') {
            BreakGlassActivations::markIdentity($user);
        }

        return $user;
    }

    /**
     * Return the service as bound.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BreakGlassService
     */
    private static function service(): BreakGlassService
    {
        $service = BreakGlassService::instance();

        self::assertInstanceOf(BreakGlassService::class, $service);

        return $service;
    }

    /**
     * Determine whether the user may take the action in the tenant, or at the
     * platform for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $user
     * @param  string|null  $tenant
     * @return bool
     */
    private static function allows(Model $user, ?string $tenant): bool
    {
        $scope = $tenant === null ? AuthorizationScope::platform() : AuthorizationScope::tenant(self::tenant($tenant));

        return $scope->within(static fn (): bool => Authorization::for($user)->can(self::ACTION));
    }

    /**
     * Return the acting principal's model.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function principalOf(ActingContext $actor): StubIdentity
    {
        return StubIdentity::query()->whereKey($actor->principal()->id)->firstOrFail();
    }

    /**
     * Record the action of each decision of a break-glass right from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private static function recordDecisions(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $decided */
        $decided = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($decided): void {
            if (!\str_starts_with($event->action, 'authorization:break-glass.')) {
                return;
            }

            $decided->append($event->action);
        });

        return $decided;
    }

    /**
     * Return the actions decided, each once.
     *
     * @param  \ArrayObject<int, string>  $decided
     * @return list<string>
     */
    private static function decided(\ArrayObject $decided): array
    {
        return \array_values(\array_unique($decided->getArrayCopy()));
    }

    /**
     * Return who ended the activation, as stored, and why.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return list<string|null>
     */
    private static function endedBy(BreakGlassActivation $activation): array
    {
        $stored = BreakGlassActivation::query()->findOrFail($activation->id);

        return [$stored->ended_by_type, $stored->ended_by_id, $stored->end_reason];
    }

    /**
     * Return the expiry of every activation, as hours and minutes, in order.
     *
     * @return list<string>
     */
    private static function expiries(): array
    {
        $format = static fn (BreakGlassActivation $activation): string => $activation->expires_at->format('H:i');

        return \array_values(BreakGlassActivation::query()->orderBy('expires_at')->get()->map($format)->all());
    }
}
