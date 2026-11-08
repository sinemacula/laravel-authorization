<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\Possession;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `Possession`, whether a delegated direct grant of a
 * permission hands out only what the actor may hand out (N77).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Possession::class)]
final class PossessionTest extends TestCase
{
    /** @var list<array{string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null, array{string, string}|null, string|null, bool}> Each further check asked, with the scope in place. */
    private array $asked = [];

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));
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
     * An actor that holds the permission across the grant, whose check of it is
     * allowed and that nothing limits, may grant it, without the grantable
     * right being asked; the check is asked in the grant's reach.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProvablePossessionAllowsTheGrant(): void
    {
        $tenant = new Reference('tenant', 'a');
        $actor  = self::holder(['tenant' => $tenant]);

        self::assertNull(Possession::refusal(...$this->grant($actor, new GrantScope($tenant, 'admin'))));
        self::assertSame([['posts:edit', null, ['tenant', 'a'], 'admin', true]], $this->asked);

        $this->forgetAsked();

        self::assertNull(Possession::refusal(...$this->grant($actor, new GrantScope($tenant, null, false))));
        self::assertSame([['posts:edit', null, ['tenant', 'a'], null, false]], $this->asked);
    }

    /**
     * An actor that does not hold the permission across the grant's reach, or
     * not for as long, is refused it as not grantable, unless the grantable
     * right is allowed on the grant's descriptor, decided in the grant's own
     * reach: its tenant, below it for a grant reaching below, and its
     * application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutPossessionTheGrantableRightDecides(): void
    {
        $tenant = new Reference('tenant', 'a');
        $actor  = self::holder(['tenant' => $tenant, 'expires' => Carbon::now()->addDay()]);

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, Possession::refusal(...$this->grant($actor, GrantScope::platform())));
        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, Possession::refusal(...$this->grant($actor, new GrantScope($tenant))));
        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, Possession::refusal(...$this->grant($actor, new GrantScope($tenant), Carbon::now()->addDays(2))));
        self::assertSame(PackagePermissions::PERMISSION_GRANTABLE, $this->asked[0][0]);
        self::assertNull(Possession::refusal(...$this->grant($actor, new GrantScope($tenant), Carbon::now()->addHour())));
        self::assertNull(Possession::refusal(...$this->grant($actor, new GrantScope($tenant), Carbon::now()->addDay())));

        self::holder(['tenant' => $tenant], PackagePermissions::PERMISSION_GRANTABLE);
        $this->forgetAsked();

        [$operation, $change, $permission, $checks] = $this->grant($actor, new GrantScope($tenant, 'admin'), null, grantable: true);

        self::assertNull(Possession::refusal($operation, $change, $permission, $checks));

        $descriptor = $this->asked[0][1]?->source;

        self::assertInstanceOf(OperationResource::class, $descriptor);
        self::assertSame(PackagePermissions::PERMISSION_GRANTABLE, $descriptor->action);
        self::assertSame('posts:edit', $descriptor->attributes()['permission']);
        [$action, , $tenantAsked, $application, $isBelow] = $this->asked[0];

        self::assertSame([PackagePermissions::PERMISSION_GRANTABLE, ['tenant', 'a'], 'admin', true], [$action, $tenantAsked, $application, $isBelow]);

        $this->forgetAsked();

        self::assertNull(Possession::refusal(...$this->grant($actor, new GrantScope($tenant, null, false), null, grantable: true)));
        self::assertSame([['tenant', 'a'], null, false], [$this->asked[0][2], $this->asked[0][3], $this->asked[0][4]]);
    }

    /**
     * The grantable right must last as long as the grant: held as a permission,
     * through grants lasting that long; allowed by a policy, through an
     * attachment lasting that long, a resource policy's never expiring, and one
     * the package did not store never counting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantableRightMustOutlastTheGrant(): void
    {
        $actor = self::holder(['expires' => Carbon::now()->addHour()]);
        $later = Carbon::now()->addDays(2);

        self::holder(['expires' => Carbon::now()->addDay()], PackagePermissions::PERMISSION_GRANTABLE);

        $refused = DecisionReason::ADMINISTRATION_NOT_GRANTABLE;

        self::assertNull(Possession::refusal(...$this->grant($actor, GrantScope::platform(), Carbon::now()->addHours(2), grantable: true)));
        self::assertSame($refused, Possession::refusal(...$this->grant($actor, GrantScope::platform(), $later, grantable: true)));

        $policy = Policy::create(['name' => 'delegates', 'document' => ['statements' => [['effect' => 'allow', 'actions' => [PackagePermissions::PERMISSION_GRANTABLE]]]]]);

        GrantService::instance()?->attachPolicy(StubIdentity::query()->findOrFail('admin'), $policy, Carbon::now()->addDays(3));

        $stored   = self::allowedBy(new StatementReference('delegates', 0, $policy->id));
        $resource = self::allowedBy(new StatementReference('operations', 0, 'resource-policy', resource: OperationResource::TYPE . ':*'));
        $inline   = self::allowedBy(new StatementReference('session', 0));

        self::assertNull(Possession::refusal(...$this->grant($actor, GrantScope::platform(), $later, grantable: $stored)));
        self::assertSame($refused, Possession::refusal(...$this->grant($actor, GrantScope::platform(), Carbon::now()->addDays(4), grantable: $stored)));
        self::assertSame($refused, Possession::refusal(...$this->grant($actor, GrantScope::platform(), null, grantable: $stored)));
        self::assertNull(Possession::refusal(...$this->grant($actor, GrantScope::platform(), null, grantable: $resource)));
        self::assertSame($refused, Possession::refusal(...$this->grant($actor, GrantScope::platform(), $later, grantable: $inline)));
        $either = self::allowedBy(new StatementReference('session', 0), new StatementReference('operations', 0, 'resource-policy', resource: OperationResource::TYPE . ':*'));

        self::assertNull(Possession::refusal(...$this->grant($actor, GrantScope::platform(), null, grantable: $either)));
    }

    /**
     * An actor that holds the permission but whose check of it is refused, or
     * whose sources cannot be read, or that something could limit, cannot be
     * proved to hold it, so it is refused as unprovable, unless the grantable
     * right is allowed, and held as long as the grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldingThatCannotBeProvedIsUnprovable(): void
    {
        $actor  = self::holder();
        $deny   = EvaluationPolicy::fromArray(['name' => 'deny', 'statements' => [['effect' => 'deny', 'actions' => ['posts:edit'], 'resources' => ['posts:9']]]]);
        $denies = new CheckSources([$deny], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, Possession::refusal(...$this->grant($actor, GrantScope::platform(), allowed: false)));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, Possession::refusal(...$this->grant($actor, GrantScope::platform(), sources: false)));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, Possession::refusal(...$this->grant($actor, GrantScope::platform(), sources: $denies)));
        self::holder([], PackagePermissions::PERMISSION_GRANTABLE);

        self::assertNull(Possession::refusal(...$this->grant($actor, GrantScope::platform(), sources: $denies, grantable: true)));
    }

    /**
     * Return an allow decided by the statements.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  ...$statements
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function allowedBy(StatementReference ...$statements): Decision
    {
        return Decision::allow(DecisionStage::ALLOW, \array_values($statements));
    }

    /**
     * Forget the further checks asked so far.
     *
     * @return void
     */
    private function forgetAsked(): void
    {
        $this->asked = [];
    }

    /**
     * Return the actor, granted the permission, `posts:edit` unless another is
     * named, platform-wide unless the options name a tenant, forever unless
     * they name an expiry.
     *
     * @param  array{tenant?: \SineMacula\Laravel\Authorization\Support\Reference, expires?: \Illuminate\Support\Carbon}  $options
     * @param  string  $permission
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Throwable
     */
    private static function holder(array $options = [], string $permission = 'posts:edit'): Subject
    {
        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        $edit = Permission::query()->firstOrCreate(['name' => $permission]);

        GrantService::instance()?->grantPermission($actor, $edit, $options['expires'] ?? null, tenant: $options['tenant'] ?? null);

        return new Subject($actor, $actor);
    }

    /**
     * Return the arguments of `Possession::refusal()` for a grant of
     * `posts:edit` in the scope, by the actor, whose further checks allow the
     * permission unless told otherwise, gather empty sources, or none, or those
     * given, and allow the grantable right only when told to, as a permission
     * held allows it, or as the decision given, recording what was asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @param  bool  $allowed
     * @param  bool|\SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @param  bool|\SineMacula\Laravel\Authorization\Evaluation\Decision  $grantable
     * @return array{
     *     \SineMacula\Laravel\Authorization\Administration\OperationResource,
     *     \SineMacula\Laravel\Authorization\Administration\OperationChange,
     *     string,
     *     \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     * }
     */
    private function grant(
        Subject $actor,
        GrantScope $scope,
        ?Carbon $expiresAt = null,
        bool $allowed = true,
        bool|CheckSources $sources = true,
        bool|Decision $grantable = false,
    ): array {
        $grantee   = StubIdentity::query()->firstOrCreate(['id' => 'grantee']);
        $operation = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $grantee, Permission::query()->firstOrCreate(['name' => 'posts:edit']), $scope, $expiresAt);
        $decide    = function (string $action, ?ResourceReference $on) use ($allowed, $grantable): Decision {
            $this->asked[] = [$action, $on, TenantScope::currentTenant(), TenantScope::currentApplication(), TenantScope::isBelowTenant()];

            $isAllowed = $action === PackagePermissions::PERMISSION_GRANTABLE ? $grantable : $allowed;

            return match (true) {
                $isAllowed instanceof Decision => $isAllowed,
                $isAllowed                     => Decision::allow(DecisionStage::ALLOW),
                default                        => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT),
            };
        };
        $gather = static fn (): ?CheckSources => match (true) {
            $sources instanceof CheckSources => $sources,
            $sources                         => new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps),
            default                          => null,
        };

        /** @var \SineMacula\Laravel\Authorization\Administration\OperationChange $change */
        $change = $operation->change;

        return [$operation, $change, 'posts:edit', new FurtherChecks($actor, $decide, $gather)];
    }
}
