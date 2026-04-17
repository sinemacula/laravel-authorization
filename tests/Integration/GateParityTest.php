<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Integration coverage asserting Gate parity for every registered
 * permission-enum case.
 *
 * For each `PermissionEnum` case the decision returned by
 * `Gate::forUser($user)->allows(...)` must equal the decision
 * returned by `Authorization::for($user)->can(...)`. The four
 * scenarios exercised here span the package's 4-step evaluator —
 * granted permission (RBAC allow), missing permission (implicit
 * deny), policy-denied (explicit deny), and resource + context
 * forwarding through the Gate tail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
#[CoversClass(AuthorizationManager::class)]
final class GateParityTest extends TestCase
{
    /** Resource identifier shared across the resource-forwarding scenarios. */
    private const string MATCHING_RESOURCE = 'arn:post:42';

    /**
     * Register the demo permission enum and re-boot the provider so
     * every enum case has a matching Gate.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
        // The default is `throw`; the provider's previous boot has
        // already defined the Gate under a fresh app, so re-booting
        // with `overwrite` avoids a spurious conflict in this test.
        $config->set('authorization.gate.on_conflict', 'overwrite');

        (new AuthorizationServiceProvider($this->app))->boot();
    }

    /**
     * Granted RBAC permission: Gate and facade both allow every
     * registered enum case that maps to a granted permission.
     *
     * @return void
     */
    public function testGrantedPermissionProducesParity(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'writer', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => PermissionEnum::PostsCreate->value, 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());
        $user->assignRole($role);

        self::assertGateParity($user, PermissionEnum::PostsCreate, expected: true);
    }

    /**
     * Missing permission: Gate and facade both implicitly deny.
     *
     * @return void
     */
    public function testMissingPermissionProducesParity(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // User has no role, no permission, no policy.
        self::assertGateParity($user, PermissionEnum::PostsDelete, expected: false);
    }

    /**
     * Explicit policy deny: Gate and facade both deny even when RBAC
     * would otherwise allow.
     *
     * @return void
     */
    public function testPolicyDenyProducesParity(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'contributor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => PermissionEnum::PostsDelete->value, 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());
        $user->assignRole($role);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'block-delete',
            'document' => [
                'statements' => [
                    ['effect' => 'deny', 'actions' => [PermissionEnum::PostsDelete->value]],
                ],
            ],
        ]));

        self::assertGateParity($user, PermissionEnum::PostsDelete, expected: false);
    }

    /**
     * Resource + context forwarding: a policy scoped to a specific
     * resource and condition context yields matching decisions from
     * both the Gate tail-argument path and the facade's
     * `(resource, context)` pair.
     *
     * @return void
     */
    public function testResourceAndContextForwardingProducesParity(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'tenant-scoped-create',
            'document' => [
                'statements' => [
                    [
                        'effect'     => 'allow',
                        'actions'    => [PermissionEnum::PostsCreate->value],
                        'resources'  => [self::MATCHING_RESOURCE],
                        'conditions' => ['tenant' => ['eq' => 'org-1']],
                    ],
                ],
            ],
        ]));

        // Matching resource + context: both surfaces allow. Gate's
        // tail spread forwards the resource and context map to the
        // closure, which `translateGateArguments()` re-assembles
        // into the manager's `(resource, context)` pair.
        $gateAllow   = Gate::forUser($user)->allows(PermissionEnum::PostsCreate->value, [self::MATCHING_RESOURCE, ['tenant' => 'org-1']]);
        $facadeAllow = Authorization::for($user)->can(PermissionEnum::PostsCreate->value, self::MATCHING_RESOURCE, ['tenant' => 'org-1']);

        self::assertTrue($facadeAllow, 'Facade should allow the tenant-scoped resource.');
        self::assertSame($facadeAllow, $gateAllow, 'Gate and facade must agree for the matching resource + context.');

        // Wrong resource: both surfaces deny.
        $gateWrong   = Gate::forUser($user)->allows(PermissionEnum::PostsCreate->value, ['arn:post:99', ['tenant' => 'org-1']]);
        $facadeWrong = Authorization::for($user)->can(PermissionEnum::PostsCreate->value, 'arn:post:99', ['tenant' => 'org-1']);
        self::assertFalse($facadeWrong);
        self::assertSame($facadeWrong, $gateWrong);

        // Wrong tenant: both surfaces deny.
        $gateTenant   = Gate::forUser($user)->allows(PermissionEnum::PostsCreate->value, [self::MATCHING_RESOURCE, ['tenant' => 'org-2']]);
        $facadeTenant = Authorization::for($user)->can(PermissionEnum::PostsCreate->value, self::MATCHING_RESOURCE, ['tenant' => 'org-2']);
        self::assertFalse($facadeTenant);
        self::assertSame($facadeTenant, $gateTenant);
    }

    /**
     * Assert the Gate decision and facade decision agree for the
     * supplied enum case.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\PermissionEnum  $case
     * @param  bool  $expected
     * @return void
     */
    private static function assertGateParity(StubIdentity $user, PermissionEnum $case, bool $expected): void
    {
        $gateDecision   = Gate::forUser($user)->allows($case->value);
        $facadeDecision = Authorization::for($user)->can($case->value);

        self::assertSame(
            $expected,
            $facadeDecision,
            "Facade decision for {$case->value} did not match expected value.",
        );

        self::assertSame(
            $facadeDecision,
            $gateDecision,
            "Gate decision for {$case->value} diverged from the facade decision.",
        );
    }
}
