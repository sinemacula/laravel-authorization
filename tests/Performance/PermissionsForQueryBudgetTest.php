<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\BulkStatusAttributes;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Query budget of `permissionsFor()` (AUTHZ-10.4): the subject's grants, roles,
 * policies and boundaries, the guardrails and the resource's policies and
 * attributes are read once for the listing, not once per action, so listing
 * fifty actions costs exactly the queries listing five costs; and a listing
 * keeps what the request has resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
final class PermissionsForQueryBudgetTest extends TestCase
{
    /**
     * Listing fifty actions in another tenant than the request's, with and
     * without a resource, costs the queries listing five costs.
     *
     * @return void
     */
    public function testFiftyActionsCostTheQueriesFiveCost(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $tenant  = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user    = StubIdentity::create(['id' => 'user-1']);
        $role    = Role::create(['name' => 'editor']);

        $role->givePermission(Permission::create(['name' => 'module:action-1']));
        $user->assignRole($role, null, $tenant);
        $user->givePermission(Permission::create(['name' => 'module:action-2']), null, $tenant);
        $user->givePermission(Permission::create(['name' => 'module:action-3']));
        $user->attachPolicy(Policy::create(['name' => 'deny-4', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['module:action-4']]]]]), null, $tenant);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $request));

        $scope    = AuthorizationScope::tenant($tenant);
        $resource = $scope->withResource(ResourceReference::record('posts', 'p1', Reference::of($tenant)));

        // Listed once first, so what a request reads once, such as the key
        // columns' types, is read before either is counted.
        $this->queriesOf(5, $scope);
        $this->queriesOf(5, $resource);

        $five  = $this->queriesOf(5, $scope);
        $fifty = $this->queriesOf(50, $scope);

        self::assertNotSame([], $five['queries']);
        self::assertSame(['module:action-1', 'module:action-2', 'module:action-3'], $fifty['listed']);
        self::assertCount(\count($five['queries']), $fifty['queries'], "Fifty actions cost other queries than five:\n" . \implode("\n", $fifty['queries']));

        $five  = $this->queriesOf(5, $resource);
        $fifty = $this->queriesOf(50, $resource);

        self::assertCount(\count($five['queries']), $fifty['queries'], "Fifty actions on a resource cost other queries than five:\n" . \implode("\n", $fifty['queries']));
    }

    /**
     * A condition reading `resource.*` reads the resource's attributes once for
     * the listing, not once for each action, whether the resource is given as a
     * reference or as a model, and whether its provider reads in bulk or one
     * record at a time: fifty actions cost the queries and the provider calls
     * five cost, and a bulk provider is asked about the one record.
     *
     * @return void
     */
    public function testAResourceConditionReadsTheAttributesOnce(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $post = ScopedPost::query()->create(['title' => 'post', 'status' => 'published']);

        $user->attachPolicy(Policy::create(['name' => 'published', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['module:*'], 'conditions' => ['eq' => ['resource.status' => 'published']]],
        ]]]));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user));

        $resources = ['a reference' => ResourceReference::record($post->getMorphClass(), self::keyOf($post)), 'a model' => $post];

        foreach ([StatusAttributes::class, BulkStatusAttributes::class] as $class) {
            foreach ($resources as $form => $resource) {
                $scope = AuthorizationScope::current()->withResource($resource);

                $this->queriesOf(5, $scope, new $class);

                $five  = $this->queriesOf(5, $scope, $fewer = new $class);
                $fifty = $this->queriesOf(50, $scope, $more = new $class);
                $label = "{$class} on {$form}";

                self::assertCount(50, $fifty['listed'], $label);
                self::assertCount(\count($five['queries']), $fifty['queries'], "Fifty actions cost other queries than five, {$label}:\n" . \implode("\n", $fifty['queries']));
                self::assertSame(self::callsOf($fewer), self::callsOf($more), $label);
                self::assertSame($class === StatusAttributes::class ? [1, []] : [0, [1]], self::callsOf($more), $label);
            }
        }
    }

    /**
     * A listing in the request's own scope reads what the request's checks
     * resolved, so with the request's resolutions warm neither it nor the check
     * after it costs a query; a listing in another scope puts them back once it
     * returns, so the check after it costs none either.
     *
     * @return void
     */
    public function testAListingKeepsWhatTheRequestResolved(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $other   = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user    = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'module:action-1']), null, $request);
        $user->givePermission(Permission::create(['name' => 'module:action-2']), null, $other);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $request));
        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions([new PermissionDefinition('module:action-1'), new PermissionDefinition('module:action-2')]));

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [DeclaredPermissions::class]);

        $manager = $this->manager();

        // Warm the request's resolutions, and what a request reads once.
        self::assertTrue($manager->can('module:action-1'));
        self::assertSame(['module:action-2'], $manager->permissionsFor(null, AuthorizationScope::tenant($other)));

        $listed = $this->counted(static fn (): array => $manager->permissionsFor(null, AuthorizationScope::current()));
        $after  = $this->counted(static fn (): bool => $manager->can('module:action-1'));

        self::assertSame([['module:action-1'], []], [$listed['result'], $listed['queries']]);
        self::assertSame([true, []], [$after['result'], $after['queries']]);

        $manager->permissionsFor(null, AuthorizationScope::tenant($other));

        $after = $this->counted(static fn (): bool => $manager->can('module:action-1'));

        self::assertSame([true, []], [$after['result'], $after['queries']]);
    }

    /**
     * Return the provider calls a listing made: how many records were asked
     * about on their own, and how many records each bulk call asked about.
     *
     * @param  object  $provider
     * @return array{int, list<int>}
     */
    private static function callsOf(object $provider): array
    {
        $bulk = $provider instanceof BulkStatusAttributes ? $provider->bulkCalls : [];

        /** @var \Tests\Fixtures\BulkChecks\BulkStatusAttributes|\Tests\Fixtures\BulkChecks\StatusAttributes $provider */
        return [\count($provider->calls), \array_map(\count(...), $bulk)];
    }

    /**
     * Return the model's key, as text.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return \is_int($key) || \is_string($key) ? (string) $key : '';
    }

    /**
     * Return what the callback returns and the queries it runs.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return array{result: TResult, queries: list<string>}
     */
    private function counted(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        try {
            $result = $callback();
        } finally {
            /** @var \Illuminate\Events\Dispatcher $events */
            $events = $this->app?->make('events');
            $events->forget(QueryExecuted::class);
        }

        return ['result' => $result, 'queries' => $queries];
    }

    /**
     * Return the queries listing the subject's actions in the scope costs, with
     * a cold cache, out of a catalogue of the given number of actions, with the
     * resource attribute provider given, or none, and the actions listed.
     *
     * @param  int  $count
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  object|null  $provider
     * @return array{queries: list<string>, listed: list<string>}
     */
    private function queriesOf(int $count, AuthorizationScope $scope, ?object $provider = null): array
    {
        $definitions = \array_map(static fn (int $index): PermissionDefinition => new PermissionDefinition('module:action-' . $index), \range(1, $count));

        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions($definitions));

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [DeclaredPermissions::class]);
        $config->set('authorization.attributes.resources', $provider === null ? [] : [(new ScopedPost)->getMorphClass() => $provider::class]);

        if ($provider !== null) {
            $this->app?->instance($provider::class, $provider);
        }

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->forgetInstance(ResolvedTenant::class);

        $manager = $this->manager();
        $user    = $manager->currentSubject()?->subject;
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $listed = $manager->permissionsFor($user, $scope);

        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->app?->make('events');
        $events->forget(QueryExecuted::class);

        return ['queries' => $queries, 'listed' => $listed];
    }

    /**
     * Return a manager made afresh, reading the configuration as it is now.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function manager(): AuthorizationManager
    {
        $this->app?->forgetInstance('authorization');
        $this->app?->forgetInstance(CheckContextFactory::class);

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make(AuthorizationManager::class);
    }
}
