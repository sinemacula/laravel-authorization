<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
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
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\TestCase;

/**
 * Query budget of `permissionsFor()` (AUTHZ-10.4): the subject's grants, roles,
 * policies and boundaries, the guardrails and the resource's policies are read
 * once for the listing, not once per action, so listing fifty actions costs
 * exactly the queries listing five costs.
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
     * Return the queries listing the subject's actions in the scope costs, with
     * a cold cache, out of a catalogue of the given number of actions, and the
     * actions listed.
     *
     * @param  int  $count
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @return array{queries: list<string>, listed: list<string>}
     */
    private function queriesOf(int $count, AuthorizationScope $scope): array
    {
        $definitions = \array_map(static fn (int $index): PermissionDefinition => new PermissionDefinition('module:action-' . $index), \range(1, $count));

        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions($definitions));

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [DeclaredPermissions::class]);

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
