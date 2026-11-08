<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\GrantHooks\PrincipalSubjectResolver;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * Sets up the tests of grant hooks (AUTHZ-11.3): an identity owning principals
 * (second stub identities), as the bound subject resolver and identity
 * directory see them, a recording hook bound on the contract, and a tree of two
 * organisations, the first with two accounts and a team below the first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait WidensGrants
{
    /**
     * Create the identity and its principals, and bind a subject resolver and
     * an identity directory that know them, the directory's list as complete as
     * given; return the identity and the principals.
     *
     * @param  string  $identity
     * @param  list<string>  $principals
     * @param  bool  $isComplete
     * @return array{\Tests\Feature\Stubs\StubIdentity, list<\Tests\Feature\Stubs\StubSecondIdentity>}
     */
    protected function principals(string $identity = 'person', array $principals = ['p1', 'p2'], bool $isComplete = true): array
    {
        $person = StubIdentity::query()->create(['id' => $identity]);
        $owned  = \array_map(static fn (string $id): StubSecondIdentity => StubSecondIdentity::query()->create(['id' => $id]), $principals);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver(\array_fill_keys($principals, $person)));
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([
            ListedIdentityDirectory::key(Reference::of($person)) => \array_map(Reference::of(...), $owned),
        ], $isComplete));

        return [$person, $owned];
    }

    /**
     * Bind a recording hook on the contract, running what the test gives it,
     * and return it.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Hooks\GrantWidening): void)|null  $during
     * @return \Tests\Fixtures\GrantHooks\RecordingGrantHook
     */
    protected function hook(?\Closure $during = null): RecordingGrantHook
    {
        $hook = new RecordingGrantHook($during);

        $this->app?->instance(GrantHook::class, $hook);

        return $hook;
    }

    /**
     * Put the fixture tenants in the closure-table tree and bind it.
     *
     * @return void
     */
    protected function closureTree(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct1'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct2'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('team1'), self::tenant('acct1'));
        ClosureTenantTree::add(self::tenant('org2'));
    }

    /**
     * Return the reference to the fixture tenant with the key.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected static function tenant(string $id): Reference
    {
        return new Reference('tenant', $id);
    }
}
