<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Hooks\WideningPhase;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\WidensGrants;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * The grant hook (AUTHZ-11.3) from the grant entry points beyond the grant
 * service itself: the trait helpers and the `authorization:grant` command,
 * trusted and delegated, each calling it when the grant widens the identity's
 * scope and not otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WideningPhase::class)]
final class GrantHookEntryPointsTest extends TestCase
{
    use ActsAsAdministrator, WidensGrants;

    /**
     * Provide each trait helper that grants.
     *
     * @return iterable<string, array{string}>
     */
    public static function helperProvider(): iterable
    {
        foreach (['assignRole', 'givePermission', 'attachPolicy', 'syncRoles', 'syncPermissions', 'syncPolicies'] as $helper) {
            yield $helper => [$helper];
        }
    }

    /**
     * Each trait helper calls the hook, trusted and delegated, for a grant in a
     * tenant the identity held nothing in, and not for one in a tenant another
     * of its principals holds a grant in.
     *
     * @param  string  $helper
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('helperProvider')]
    public function testEveryHelperCallsTheHookOnlyWhenTheGrantWidens(string $helper): void
    {
        $actor = self::administrator(['authorization:*', 'posts:*']);

        foreach (['trusted' => null, 'delegated' => $actor] as $mode => $acting) {
            [, [$first, $second]] = $this->principals('person-' . $mode, ['first-' . $mode, 'second-' . $mode]);

            $hook = $this->hook();

            self::grantThrough($helper, $first, $acting, 'widening-' . $mode);
            self::grantThrough($helper, $second, $acting, 'held-' . $mode);

            self::assertSame([[WideningReason::NEW_TENANT->value]], $hook->reasons(), $mode);
            self::assertSame($acting === null, $hook->widenings[0]->isTrusted);
        }
    }

    /**
     * The `authorization:grant` command calls the hook, trusted and with an
     * actor, for a role the identity does not hold, and not for one it holds
     * unchanged; a refusal fails the command with the hook's message, nothing
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantCommandCallsTheHook(): void
    {
        self::administrator(['authorization:*']);

        [, [$principal]] = $this->principals();

        Role::query()->create(['name' => 'editor']);
        Role::query()->create(['name' => 'author']);

        $hook     = $this->hook();
        $identity = StubSecondIdentity::class . ':p1';

        self::assertSame(0, Artisan::call('authorization:grant', ['identity' => $identity, 'role' => 'editor']));
        self::assertSame(0, Artisan::call('authorization:grant', ['identity' => $identity, 'role' => 'editor']));
        self::assertSame(0, Artisan::call('authorization:grant', ['identity' => $identity, 'role' => 'author', '--actor' => StubIdentity::class . ':admin-1']));

        self::assertSame([[WideningReason::PLATFORM->value], [WideningReason::PLATFORM->value]], $hook->reasons());
        self::assertSame([true, false], [$hook->widenings[0]->isTrusted, $hook->widenings[1]->isTrusted]);

        $this->app?->instance(GrantHook::class, new RefusingGrantHook);

        Role::query()->create(['name' => 'refused']);

        self::assertSame(1, Artisan::call('authorization:grant', ['identity' => $identity, 'role' => 'refused']));
        self::assertStringContainsString('Refused by the test hook.', Artisan::output());
        self::assertFalse($principal->fresh()?->hasRole('refused'));
    }

    /**
     * Grant the principal a new grant named for the name in the first account,
     * through the trait helper given, as the actor given or trusted.
     *
     * @param  string  $helper
     * @param  \Tests\Feature\Stubs\StubSecondIdentity  $grantee
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  string  $name
     * @return \Tests\Feature\Stubs\StubSecondIdentity
     *
     * @throws \Throwable
     */
    private static function grantThrough(string $helper, StubSecondIdentity $grantee, ?ActingContext $actor, string $name): StubSecondIdentity
    {
        $tenant = self::tenant('acct1');

        return match ($helper) {
            'assignRole'      => $grantee->assignRole(self::role($name), tenant: $tenant, actor: $actor),
            'givePermission'  => $grantee->givePermission(self::permission($name), tenant: $tenant, actor: $actor),
            'attachPolicy'    => $grantee->attachPolicy(self::denying($name), tenant: $tenant, actor: $actor),
            'syncRoles'       => $grantee->syncRoles([self::role($name)], $tenant, actor: $actor),
            'syncPermissions' => $grantee->syncPermissions([self::permission($name)], $tenant, actor: $actor),
            default           => $grantee->syncPolicies([self::denying($name)], $tenant, actor: $actor),
        };
    }

    /**
     * Create a platform role with the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name): Role
    {
        return Role::query()->create(['name' => $name]);
    }

    /**
     * Create a platform permission named for the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->create(['name' => 'posts:' . $name]);
    }

    /**
     * Create a policy that only denies.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function denying(string $name): Policy
    {
        return Policy::query()->create(['name' => 'deny-' . $name, 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);
    }
}
