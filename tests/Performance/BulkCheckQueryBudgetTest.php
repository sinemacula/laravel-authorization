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
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\BulkStatusAttributes;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Query budget of a bulk check (AUTHZ-10.3): a check over many resources of one
 * type and tenant reads the subject's grants and policies once, and the
 * resources' tenants, the policies attached to them and their attributes in
 * bulk, so it costs exactly the queries a check over one of them costs, never
 * one more per resource. Over a tenant tree that is read from the database,
 * each tenant's place in the tree is read once, so the tree costs what the
 * distinct tenants cost, whatever the number of resources.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CheckBatch::class)]
final class BulkCheckQueryBudgetTest extends TestCase
{
    /** @var string The action every check decides. */
    private const string ACTION = 'posts:read';

    /**
     * Checking a hundred posts named by pair costs the queries checking one
     * costs: one for their tenants, one for the policies attached to them and
     * their type, and one for their attributes, whatever the number.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHundredResourcesCostTheQueriesOneCosts(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $posts  = [];

        for ($index = 0; $index < 100; $index++) {
            $status  = $index % 2 === 0 ? 'published' : 'draft';
            $posts[] = TenantScopedPost::query()->create(['title' => 'p', 'status' => $status, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()]);
        }

        $user->givePermission(Permission::create(['name' => 'posts:list']), null, $tenant);
        $this->attach([TenantScopedPost::class, (string) $posts[8]->getKey()], 'deny', $tenant); // @phpstan-ignore cast.string
        $this->attach(TenantScopedPost::class, 'allow', $tenant);
        $this->resolve($user, $tenant);

        // Two first, so what a request reads once, such as the key columns'
        // types, is read before either is counted; then a draft, refused by its
        // type's policy, so its check reads the permissions too, as the
        // hundred's drafts do.
        $this->queriesOf(\array_slice($posts, 2, 2));

        $one      = $this->queriesOf(\array_slice($posts, 1, 1));
        $hundred  = $this->queriesOf($posts);
        $allowed  = $this->manager()->canEach(self::ACTION, self::pairs($posts));
        $expected = \array_map(static fn (int $index): bool => $index % 2 === 0 && $index !== 8, \range(0, 99));

        self::assertSame($expected, $allowed);
        self::assertCount(\count($one['all']), $hundred['all'], "A hundred resources cost other queries than one:\n" . \implode("\n", $hundred['all']));
        self::assertCount(1, $hundred['tenants'], \implode("\n", $hundred['tenants']));
        self::assertCount(1, $hundred['attachments'], \implode("\n", $hundred['attachments']));
        self::assertCount(1, $hundred['attributes'], \implode("\n", $hundred['attributes']));
    }

    /**
     * Over a closure-table tree, checking a hundred posts of a tenant below the
     * request's reads the tree as checking one does, and a hundred posts spread
     * over four such tenants read it as four posts, one in each, do: once for
     * each tenant, never once more per post.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTreeIsReadOncePerTenantNotPerResource(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        $org      = StubTenant::query()->create(['id' => 'o1', 'name' => 'o1']);
        $accounts = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['a1', 'a2', 'a3', 'a4']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $posts    = [];

        ClosureTenantTree::add(Reference::of($org));

        foreach ($accounts as $account) {
            ClosureTenantTree::add(Reference::of($account), Reference::of($org));
        }

        for ($index = 0; $index < 100; $index++) {
            $account = $accounts[$index % 4];
            $posts[] = TenantScopedPost::query()->create(['title' => 'p', 'status' => 'published', 'tenant_type' => $account->getMorphClass(), 'tenant_id' => $account->getKey()]);
        }

        $user->givePermission(Permission::create(['name' => self::ACTION]), null, $org, true);
        $this->resolve($user, $org);

        $sameTenant = \array_values(\array_filter($posts, static fn (TenantScopedPost $post): bool => $post->getAttribute('tenant_id') === 'a1'));

        $this->queriesOf(\array_slice($posts, 0, 2));

        $one      = $this->queriesOf(\array_slice($sameTenant, 0, 1));
        $tenant   = $this->queriesOf($sameTenant);
        $four     = $this->queriesOf(\array_slice($posts, 0, 4));
        $hundred  = $this->queriesOf($posts);
        $allowed  = $this->manager()->canEach(self::ACTION, self::pairs($posts));
        $describe = static fn (array $queries): string => \implode("\n", $queries['tree']);

        self::assertSame(\array_fill(0, 100, true), $allowed);
        self::assertNotSame([], $one['tree']);
        self::assertCount(\count($one['tree']), $tenant['tree'], $describe($tenant));
        self::assertCount(\count($four['tree']), $hundred['tree'], $describe($hundred));
        self::assertCount(\count($four['all']), $hundred['all'], \implode("\n", $hundred['all']));
    }

    /**
     * Return the queries checking the posts, named by pair, costs with a cold
     * cache: all of them, and those reading the posts' tenants, the policies
     * attached to them, their attributes and the tenant tree.
     *
     * @param  list<\Tests\Fixtures\QueryScoping\TenantScopedPost>  $posts
     * @return array{all: list<string>, tenants: list<string>, attachments: list<string>, attributes: list<string>, tree: list<string>}
     */
    private function queriesOf(array $posts): array
    {
        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->forgetInstance(ResolvedTenant::class);

        $manager = $this->manager();
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $manager->canEach(self::ACTION, self::pairs($posts));

        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->app?->make('events');
        $events->forget(QueryExecuted::class);

        $posts = \array_values(\array_filter($queries, static fn (string $sql): bool => \str_contains($sql, 'scoped_posts')));

        return [
            'all'         => $queries,
            'tenants'     => \array_values(\array_filter($posts, static fn (string $sql): bool => !\str_contains($sql, 'select *'))),
            'attachments' => \array_values(\array_filter($queries, static fn (string $sql): bool => \str_contains($sql, 'resource_policies'))),
            'attributes'  => \array_values(\array_filter($posts, static fn (string $sql): bool => \str_contains($sql, 'select *'))),
            'tree'        => \array_values(\array_filter($queries, static fn (string $sql): bool => \str_contains($sql, ClosureTenantTree::TABLE))),
        ];
    }

    /**
     * Return each post named by its `(type, id)` pair.
     *
     * @param  list<\Tests\Fixtures\QueryScoping\TenantScopedPost>  $posts
     * @return list<array{class-string, string}>
     */
    private static function pairs(array $posts): array
    {
        return \array_map(static function (TenantScopedPost $post): array {
            $key = $post->getKey();

            return [TenantScopedPost::class, \is_int($key) || \is_string($key) ? (string) $key : ''];
        }, $posts);
    }

    /**
     * Attach a policy allowing the user to read a published post, or denying
     * everyone reading it, to the target, in the tenant.
     *
     * @param  array{class-string, string}|class-string  $target
     * @param  string  $effect
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     *
     * @throws \Throwable
     */
    private function attach(array|string $target, string $effect, StubTenant $tenant): void
    {
        $published = ['eq' => ['resource.status' => 'published']];
        $statement = $effect === 'deny'
            ? ['effect' => 'deny', 'actions' => [self::ACTION]]
            : ['effect' => 'allow', 'actions' => [self::ACTION], 'principals' => [(new StubIdentity)->getMorphClass() . ':user-1'], 'conditions' => $published];
        $policy = Policy::create(['name' => "{$effect}-published", 'document' => ['statements' => [$statement]]]);

        /** @var \SineMacula\Laravel\Authorization\Services\ResourcePolicyService $service */
        $service = $this->app?->make(ResourcePolicyService::class);
        $service->attach($policy, $target, $tenant);
    }

    /**
     * Resolve the request about the user in the tenant, with the posts'
     * attributes read in bulk.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     */
    private function resolve(StubIdentity $user, StubTenant $tenant): void
    {
        $provider = new BulkStatusAttributes;

        $this->app?->instance(BulkStatusAttributes::class, $provider);
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.attributes.resources', [(new TenantScopedPost)->getMorphClass() => BulkStatusAttributes::class]);
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
