<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the resolution of the guardrails that apply to a check: the
 * platform's and those of the check's tenant and its ancestors, the resource's
 * tenant when it has one, read in one query, through the resolution cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardrailResolver::class)]
final class GuardrailResolverTest extends TestCase
{
    use ActsAsTenant;

    /**
     * With no guardrail set, none applies, in the platform and in a tenant.
     *
     * @return void
     */
    public function testNoGuardrailMeansNone(): void
    {
        $tenant = self::createTenant('tenant-a');

        self::assertSame([], (new GuardrailResolver)->guardrailsFor(null));
        self::assertSame([], TenantScope::within($tenant, null, static fn (): array => (new GuardrailResolver)->guardrailsFor(null)));
    }

    /**
     * The guardrails that apply are the platform's and those of the tenant and
     * every ancestor, a tenant's reaching its whole subtree, and never a
     * sibling's or a descendant's; with no tenant, the platform's alone.
     *
     * @return void
     */
    public function testThePlatformsTheTenantsAndItsAncestorsApply(): void
    {
        [$org, $account, $team, $sibling] = self::tree();

        self::rail('platform');
        self::rail('in-org', $org);
        self::rail('in-account', $account);
        self::rail('in-team', $team);
        self::rail('in-sibling', $sibling);

        self::assertSame(['platform'], self::names());
        self::assertSame(['in-org', 'platform'], self::names($org));
        self::assertSame(['in-account', 'in-org', 'platform'], self::names($account));
        self::assertSame(['in-account', 'in-org', 'in-team', 'platform'], self::names($team));
        self::assertSame(['in-org', 'in-sibling', 'platform'], self::names($sibling));
    }

    /**
     * A guardrail naming half a tenant, a key without a type or a type without
     * a key, which the package never writes, caps everywhere, as the platform's
     * do: at the platform, in every tenant and below it, and on a resource of a
     * tenant decided outside it.
     *
     * @return void
     */
    public function testAGuardrailNamingHalfATenantAppliesEverywhere(): void
    {
        [$org, $account, $team, $sibling] = self::tree();

        self::rail('in-account', $account);

        $keyless  = self::rail('keyless');
        $typeless = self::rail('typeless');

        DB::table('guardrails')->where('policy_id', $keyless->id)->update(['tenant_type' => $org->getMorphClass()]);
        DB::table('guardrails')->where('policy_id', $typeless->id)->update(['tenant_id' => 'org']);

        $half = ['keyless', 'typeless'];

        self::assertSame($half, self::names());
        self::assertSame($half, self::names($org));
        self::assertSame(['in-account', ...$half], self::names($account));
        self::assertSame(['in-account', ...$half], self::names($team));
        self::assertSame($half, self::names($sibling));
        self::assertSame(['in-account', ...$half], self::sorted((new GuardrailResolver)->guardrailsFor(ResourceReference::record('posts', '1', Reference::of($account)))));
    }

    /**
     * A check on a resource of a tenant reads that tenant's guardrails, also
     * when it is decided at platform scope or in another tenant; a resource
     * with no tenant, or none at all, reads the guardrails of the scope the
     * check is decided in.
     *
     * @return void
     */
    public function testTheResourcesTenantDecidesWhichGuardrailsApply(): void
    {
        [$org, $account] = self::tree();

        self::rail('platform');
        self::rail('in-org', $org);
        self::rail('in-account', $account);

        $owned    = ResourceReference::record('posts', '7', Reference::of($account));
        $unowned  = ResourceReference::record('posts', '8');
        $resolver = new GuardrailResolver;

        self::assertSame(['in-account', 'in-org', 'platform'], self::sorted($resolver->guardrailsFor($owned)));
        self::assertSame(['platform'], self::sorted($resolver->guardrailsFor($unowned)));
        self::assertSame(['in-account', 'in-org', 'platform'], TenantScope::within($account, null, static fn (): array => self::sorted($resolver->guardrailsFor($owned))));
        self::assertSame(['in-account', 'in-org', 'platform'], TenantScope::within($org, null, static fn (): array => self::sorted($resolver->guardrailsFor($owned))));
        self::assertSame(['in-org', 'platform'], TenantScope::within($org, null, static fn (): array => self::sorted($resolver->guardrailsFor($unowned))));
        self::assertNull(TenantScope::currentTenant());
    }

    /**
     * A policy set as a guardrail on more than one tenant of the chain is read
     * once, with its stored key.
     *
     * @return void
     */
    public function testAPolicySetOnTwoScopesIsReadOnce(): void
    {
        $tenant = self::createTenant('tenant-a');
        $rail   = self::rail('both');

        self::set($rail, $tenant);

        $guardrails = TenantScope::within($tenant, null, static fn (): array => (new GuardrailResolver)->guardrailsFor(null));

        self::assertCount(1, $guardrails);
        self::assertSame($rail->id, $guardrails[0]->id);
        self::assertNull($guardrails[0]->resource);
    }

    /**
     * The guardrails and their documents are read in one query however many
     * apply, and read again in the request they ask nothing more.
     *
     * @return void
     */
    public function testReadsInOneQueryThenFromTheCache(): void
    {
        [$org, $account] = self::tree();

        self::rail('platform');
        self::rail('in-org', $org);
        self::rail('in-account', $account);

        $this->actAsTenant($account);

        // The tenant and its ancestors are read before the queries are counted.
        self::assertCount(2, TenantScope::currentChain()->tenants);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame(['in-account', 'in-org', 'platform'], self::sorted((new GuardrailResolver)->guardrailsFor(null)));
        self::assertCount(1, DB::getQueryLog());

        DB::flushQueryLog();

        self::assertCount(3, (new GuardrailResolver)->guardrailsFor(null));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Without a resolution cache bound, the guardrails are read straight from
     * the database.
     *
     * @return void
     */
    public function testReadsFromTheDatabaseWithoutACache(): void
    {
        self::rail('platform');

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertSame(['platform'], self::names());
    }

    /**
     * With a persistent store, the guardrails are kept across requests, and
     * read afresh once a guardrail is set or any policy is rewritten.
     *
     * @return void
     */
    public function testAPersistentEntryHoldsUntilAWriteChangesIt(): void
    {
        $store = new Repository(new ArrayStore);
        $rail  = self::rail('platform');

        self::request($store);

        self::assertSame(['platform'], self::names());

        self::request($store);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame(['platform'], self::names());
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();

        (new VersionedStore($store, 'authz'))->bump([(new VersionedStore($store, 'authz'))->guardrailsKey()]);
        DB::table('guardrails')->where('policy_id', $rail->id)->delete();
        self::request($store);

        self::assertSame([], self::names());
    }

    /**
     * The resolution pins the version every guardrail entry shares before it
     * reads, and lists each guardrail for evaluation.
     *
     * @return void
     */
    public function testTheResolutionPinsTheSharedVersion(): void
    {
        $pins = new ResolutionPins(new VersionedStore(new Repository(new ArrayStore), 'authz'));

        self::rail('platform');

        $resolution = GuardrailResolver::resolve($pins);

        self::assertSame(['authz:version:guardrails'], \array_keys($pins->tokens()));
        self::assertSame(['platform'], self::sorted($resolution->value));
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * A guardrail whose document cannot be read is never skipped: its exception
     * is thrown, so it denies every check in its scope.
     *
     * @return void
     */
    public function testAnUnreadableGuardrailIsThrown(): void
    {
        $rail = self::rail('platform');

        DB::table('policies')->where('id', $rail->getKey())->update(['document' => '{"statements": "broken"}']);

        $this->expectException(InvalidPolicyDocumentException::class);

        (new GuardrailResolver)->guardrailsFor(null);
    }

    /**
     * Create an organisation with an account below it, a team below that and a
     * sibling of the account, and bind the tree.
     *
     * @return list<\Tests\Feature\Stubs\StubTenant>
     */
    private function tree(): array
    {
        [$org, $account, $team, $sibling] = \array_map(self::createTenant(...), ['org', 'account', 'team', 'sibling']);

        $tree = (new StubTenantTree)
            ->put(Reference::of($account), Reference::of($org))
            ->put(Reference::of($team), Reference::of($account))
            ->put(Reference::of($sibling), Reference::of($org));

        $this->app?->instance(TenantTree::class, $tree);

        return [$org, $account, $team, $sibling];
    }

    /**
     * Start a new request with the store as the persistent tier.
     *
     * @param  \Illuminate\Cache\Repository  $store
     * @return void
     */
    private static function request(Repository $store): void
    {
        app()->instance(ResolutionCache::class, new ResolutionCache($store, 300, 'authz'));
    }

    /**
     * Return the names of the guardrails that apply in the tenant, or the
     * platform, sorted.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return list<string>
     */
    private static function names(?StubTenant $tenant = null): array
    {
        return TenantScope::within($tenant, null, static fn (): array => self::sorted((new GuardrailResolver)->guardrailsFor(null)));
    }

    /**
     * Return the names of the policies, sorted.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function sorted(array $policies): array
    {
        $names = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        \sort($names);

        return $names;
    }

    /**
     * Create a guardrail policy allowing `posts:read`, set on the tenant or the
     * platform.
     *
     * @param  string  $name
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function rail(string $name, ?StubTenant $tenant = null): Policy
    {
        $policy = Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        self::set($policy, $tenant);

        return $policy;
    }

    /**
     * Set the policy as a guardrail on the tenant or the platform, past the
     * guardrail service.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return void
     */
    private static function set(Policy $policy, ?StubTenant $tenant): void
    {
        DB::table('guardrails')->insert(['policy_id' => $policy->id, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()]);
    }
}
