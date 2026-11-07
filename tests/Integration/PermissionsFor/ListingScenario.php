<?php

declare(strict_types = 1);

namespace Tests\Integration\PermissionsFor;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Random\Engine\Mt19937;
use Random\Randomizer;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\TenantScopedPost;

/**
 * One random scenario of the `permissionsFor()` parity property: a catalogue of
 * the package's permissions, some enums and a provider's definitions, some
 * declared for a guard; the subject's grants, roles, policies, boundary and a
 * guardrail, and the policies attached to the posts' type and records, with
 * conditions over the caller's input, the subject, the frozen clock, the
 * resource's status and an authentication requirement; the request's tenant,
 * application and session; the manager the listing runs through, the subject it
 * names (a guest, a resolved subject or a model) and the scope it names: the
 * platform, a tenant or a descendant one, an application or none, and a post
 * named one way or another, or none. Every choice is logged, so a failure names
 * the scenario.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class ListingScenario
{
    /** @var list<string> The actions grants and statements name, the catalogue's and others. */
    private const array ACTIONS = ['posts:create', 'posts:delete', 'posts.publish', 'posts:archive', 'posts:view', 'reports:view', 'other:act'];

    /** @var list<string> The names a provider may declare, none with metadata an enum gives it otherwise. */
    private const array PROVIDED = ['posts:delete', 'posts:view', 'reports:view', 'posts:archive'];

    /** @var string The instant every scenario is frozen at. */
    private const string NOW = '2026-06-01 12:00:00';

    /** @var list<string> What happened, in order. */
    public array $log = [];

    /** @var \SineMacula\Laravel\Authorization\Subject|null The request's subject. */
    public ?Subject $request = null;

    /** @var array<string, mixed> The caller's context. */
    public array $context = [];

    /** @var \Random\Randomizer Draws every choice from the seed. */
    private readonly Randomizer $random;

    /** @var list<\Tests\Feature\Stubs\StubTenant|null> The tenants a grant, a post or the scope may be in. */
    private array $tenants = [];

    /** @var list<\Illuminate\Database\Eloquent\Model> The posts created. */
    private array $posts = [];

    /** @var list<string> The keys of the roles created. */
    private array $roles = [];

    /** @var \Tests\Feature\Stubs\StubIdentity The subject. */
    private readonly StubIdentity $user;

    /** @var string How the manager is decorated: as it is, capped or with a policy override. */
    private string $decoration = 'current';

    /** @var list<string> The cap of a capped manager. */
    private array $cap = [];

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Policy|null The override of a manager with policies. */
    private ?EvaluationPolicy $override = null;

    /**
     * Create a scenario drawn from the seed.
     *
     * @param  int  $seed
     * @param  \Illuminate\Foundation\Application  $app
     */
    public function __construct(

        /** The seed every choice is drawn from. */
        private readonly int $seed,

        /** The application the scenario binds its request in. */
        private readonly Application $app,
    ) {
        $this->random = new Randomizer(new Mt19937($seed));
        $this->user   = StubIdentity::create(['id' => 'u1']);
    }

    /**
     * Build the scenario's state: the catalogue, the request, the grants and
     * policies, the posts, their attachments and attribute provider, how the
     * manager is decorated and the caller's context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function build(): void
    {
        Carbon::setTestNow(Carbon::parse(self::NOW));

        $this->catalogue();
        $this->request();
        $this->grants();
        $this->policies();
        $this->posts();
        $this->attachments();
        $this->caller();
    }

    /**
     * Return the manager the listing runs through: made afresh for the request,
     * decorated as drawn.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    public function manager(): AuthorizationManager
    {
        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app->make(AuthorizationManager::class);

        return match ($this->decoration) {
            'capped'       => $manager->capped($this->cap),
            'withPolicies' => $manager->withPolicies([$this->override ?? EvaluationPolicy::fromArray(['name' => 'none', 'statements' => []])]),
            default        => $manager,
        };
    }

    /**
     * Draw the subject the listing names: a guest, a resolved subject with a
     * session or without one, or the request's model.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|\Tests\Feature\Stubs\StubIdentity|null
     */
    public function subject(): StubIdentity|Subject|null
    {
        $subject = $this->pick(['guest', 'subject', 'subject', 'model', 'model']);

        $this->log[] = "subject {$subject}";

        return match ($subject) {
            'guest'   => null,
            'subject' => new Subject($this->user, $this->user, null, null, $this->pick([null, 'web']), $this->pick([null, 'session-2'])),
            default   => $this->user,
        };
    }

    /**
     * Draw the scope the listing names: the platform, a tenant or a descendant
     * one, on an application or none, with a post named one way or another, or
     * none.
     *
     * @return \SineMacula\Laravel\Authorization\Support\AuthorizationScope
     */
    public function scope(): AuthorizationScope
    {
        $tenant      = $this->pick($this->tenants);
        $application = $this->pick([null, 'admin', 'mobile']);
        $scope       = $tenant === null ? AuthorizationScope::platform($application) : AuthorizationScope::tenant($this->pick([$tenant, Reference::of($tenant)]), $application);
        $resource    = $this->resource();

        $this->log[] = 'scope ' . self::nameOf($tenant) . ' on ' . ($application ?? 'no application');

        return $scope->withResource($resource);
    }

    /**
     * Return how to replay the scenario, and what it did.
     *
     * @return string
     */
    public function replay(): string
    {
        return "Replay with AUTHZ_PARITY_SEED={$this->seed} AUTHZ_PARITY_RUNS=1.\n" . \implode("\n", $this->log);
    }

    /**
     * Configure the catalogue: one of the enums or none, and a provider
     * declaring some names, each for a guard or every one, or no provider.
     *
     * @return void
     */
    private function catalogue(): void
    {
        // Both enums declare posts:create, with metadata and without, so the
        // catalogue would refuse them together.
        $enums       = $this->pick([[], [PermissionEnum::class], [CataloguePermission::class]]);
        $definitions = [];

        for ($index = $this->random->getInt(0, 4); $index > 0; $index--) {
            $definitions[] = new PermissionDefinition($this->pick(self::PROVIDED), null, null, $this->pick([null, null, 'web', 'api']));
        }

        $this->app->instance(DeclaredPermissions::class, new DeclaredPermissions($definitions));

        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', $enums);
        $config->set('authorization.permission_providers', $definitions === [] ? [] : [DeclaredPermissions::class]);

        $describe    = static fn (PermissionDefinition $definition): string => $definition->name . '@' . ($definition->guard ?? 'any');
        $this->log[] = 'enums ' . \json_encode($enums) . ', provided ' . \implode(', ', \array_map($describe, $definitions));
    }

    /**
     * Resolve the request: the subject in a tenant, an application and a
     * session, or none of them, with a requirement checker that meets every
     * requirement in a session, or none, over a flat tree or a closure table in
     * which the first organisation is above an account, itself above a
     * sub-account, beside a second organisation.
     *
     * @return void
     */
    private function request(): void
    {
        $tenants       = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['o1', 'a1', 's1', 'o2']);
        $this->tenants = [null, ...$tenants];
        $isClosure     = $this->random->getInt(0, 2) > 0;

        $this->app->instance(TenantTree::class, $isClosure ? new ClosureTenantTree : new FlatTenantTree);

        if ($isClosure) {
            [$o1, $a1, $s1, $o2] = \array_map(Reference::of(...), $tenants);

            ClosureTenantTree::add($o1);
            ClosureTenantTree::add($a1, $o1);
            ClosureTenantTree::add($s1, $a1);
            ClosureTenantTree::add($o2);
        }

        $active        = $this->pick($this->tenants);
        $application   = $this->pick([null, 'admin']);
        $isMet         = $this->random->getInt(0, 1) === 1;
        $this->request = new Subject($this->user, $this->user, $active, $application, $this->pick([null, 'web']), $this->pick([null, 'session-1']));

        $this->app->instance(SubjectResolver::class, new FixedSubjectResolver($this->request));
        $this->app->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker($isMet));

        $this->log[] = ($isClosure ? 'closure tree' : 'flat tree') . ', request in ' . self::nameOf($active) . ' on ' . ($application ?? 'no application')
            . ', session ' . ($this->request->session ?? 'none') . ', requirements ' . ($isMet ? 'met' : 'unmet');
    }

    /**
     * Grant the subject permissions and roles, each in a tenant or the
     * platform, reaching its subtree or not, for an application or every one,
     * some roles through a parent.
     *
     * @return void
     */
    private function grants(): void
    {
        for ($index = $this->random->getInt(1, 5); $index > 0; $index--) {
            $permission = Permission::query()->firstOrCreate(['name' => $this->pick([...self::ACTIONS, 'posts:*', '*', PackagePermissions::GUARDRAILS_MANAGE])]);
            $tenant     = $this->pick([null, ...$this->tenants]);
            $app        = $this->pick([null, null, 'admin', 'mobile']);
            $kind       = $this->pick(['permission', 'permission', 'role', 'inherited-role']);
            $isSubtree  = $this->random->getInt(0, 2) > 0;

            $this->log[] = "grant {$kind} {$permission->name} in " . self::nameOf($tenant) . ($isSubtree ? ' and below' : ' alone') . ' for ' . ($app ?? 'every application');

            if ($kind === 'permission') {
                $this->user->givePermission($permission, null, $tenant, $isSubtree, $app);

                continue;
            }

            $holder = Role::create(['name' => 'role-' . $index]);
            $role   = $kind === 'role' ? $holder : Role::create(['name' => 'child-' . $index, 'parent_id' => $holder->id]);

            $holder->givePermission($permission);
            $this->user->assignRole($role, null, $tenant, $isSubtree, $app);

            $this->roles[] = $role->id;
        }
    }

    /**
     * Attach the subject's policies, and set a boundary and a guardrail, each
     * sometimes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function policies(): void
    {
        // A cap's statements: an allow of every action, the posts' or one, with
        // conditions as any statement's.
        $cap = fn (): array => [['effect' => 'allow', 'actions' => [$this->pick(['*', 'posts:*', 'posts:create', 'reports:view'])], ...$this->conditions()]];

        for ($index = $this->random->getInt(0, 3); $index > 0; $index--) {
            $tenant = $this->pick($this->tenants);

            $this->log[] = 'identity policy in ' . self::nameOf($tenant);

            $this->user->attachPolicy($this->policy('identity-' . $index, $this->statements(false)), null, $tenant, $this->random->getInt(0, 2) > 0);
        }

        if ($this->random->getInt(0, 3) === 0) {
            $this->app->make(BoundaryService::class)->set($this->user, $this->policy('boundary', $cap()));
        }

        if ($this->random->getInt(0, 3) !== 0) {
            return;
        }

        $admin  = StubIdentity::create(['id' => 'guardrail-admin']);
        $tenant = $this->pick($this->tenants);

        $admin->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAILS_MANAGE]));
        $this->app->make(GuardrailService::class)->set($this->policy('guardrail', $cap()), $tenant, $admin);

        $this->log[] = 'guardrail in ' . self::nameOf($tenant);
    }

    /**
     * Create the posts: tenantless ones and tenant-owned ones of every tenant
     * or none, each published or a draft, and register their attribute
     * provider.
     *
     * @return void
     */
    private function posts(): void
    {
        for ($index = $this->random->getInt(1, 4); $index > 0; $index--) {
            $tenant  = $this->pick($this->tenants);
            $status  = $this->pick(['published', 'draft']);
            $isOwned = $this->random->getInt(0, 2) > 0;

            $this->posts[] = $isOwned
                ? TenantScopedPost::query()->create(['title' => 'p', 'status' => $status, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()])
                : ScopedPost::query()->create(['title' => 'p', 'status' => $status]);

            $this->log[] = ($isOwned ? 'post in ' . self::nameOf($tenant) : 'tenantless post') . ", {$status}";
        }

        $provider = new StatusAttributes;

        // Failing for every post sometimes, so a listing on one that reads its
        // status throws as its check does.
        if ($this->random->getInt(0, 4) === 0) {
            $provider->failing = \array_map(self::keyOf(...), $this->posts);

            $this->log[] = 'status lookup failing';
        }

        $this->app->instance(StatusAttributes::class, $provider);
        $this->app->make(ConfigRepository::class)->set('authorization.attributes.resources', [
            (new ScopedPost)->getMorphClass()       => StatusAttributes::class,
            (new TenantScopedPost)->getMorphClass() => StatusAttributes::class,
        ]);
    }

    /**
     * Attach policies to the posts' types and to some posts, each in a tenant
     * or the platform, reaching its subtree or not, for an application or every
     * one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function attachments(): void
    {
        for ($index = $this->random->getInt(0, 3); $index > 0; $index--) {
            $post      = $this->pick($this->posts);
            $tenant    = $this->pick($this->tenants);
            $isSubtree = $this->random->getInt(0, 2) > 0;
            $app       = $this->pick([null, null, 'admin']);
            $isRecord  = $this->random->getInt(0, 1) === 1;
            $target    = $isRecord ? [$post::class, self::keyOf($post)] : $post::class;

            $this->log[] = 'attached to ' . ($isRecord ? 'post ' . self::keyOf($post) : $post::class) . ' in ' . self::nameOf($tenant) . ($isSubtree ? ' and below' : ' alone');

            $this->app->make(ResourcePolicyService::class)->attach($this->policy('resource-' . $index, $this->statements(true)), $target, $tenant, $isSubtree, $app);
        }
    }

    /**
     * Draw how the caller asks: through a manager as it is, capped or with a
     * policy override, and with what context.
     *
     * @return void
     */
    private function caller(): void
    {
        $this->decoration = $this->pick(['current', 'current', 'capped', 'withPolicies']);
        $this->cap        = [$this->pick(['posts:*', 'posts:create', 'reports:*', '*'])];
        $this->override   = EvaluationPolicy::fromArray(['name' => 'override', 'statements' => $this->statements(false)]);
        $this->context    = $this->pick([[], ['flag' => 'on'], ['flag' => 'off']]);

        $this->log[] = "manager {$this->decoration}" . ($this->decoration === 'capped' ? ' to ' . $this->cap[0] : '') . ', context ' . \json_encode($this->context);
    }

    /**
     * Return the resource the scope names: a post by model, by pair or by
     * reference, its type, an opaque string, or none.
     *
     * @return mixed
     */
    private function resource(): mixed
    {
        $post = $this->pick($this->posts);
        $id   = self::keyOf($post);
        $kind = $this->pick(['none', 'none', 'model', 'pair', 'reference', 'type', 'opaque']);

        $this->log[] = "resource {$kind} of " . \class_basename($post) . " {$id}";

        return match ($kind) {
            'model'     => $post,
            'pair'      => [$post::class, $id],
            'reference' => ResourceReference::record($post->getMorphClass(), $id),
            'type'      => $post::class,
            'opaque'    => 'posts:' . $id,
            default     => null,
        };
    }

    /**
     * Return a stored policy of the statements, logged.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private function policy(string $name, array $statements): Policy
    {
        $this->log[] = "policy {$name}: " . \json_encode($statements, \JSON_UNESCAPED_SLASHES);

        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Return one to three statements, an allow naming its principals when it is
     * a resource policy's.
     *
     * @param  bool  $isResourcePolicy
     * @return list<array<string, mixed>>
     */
    private function statements(bool $isResourcePolicy): array
    {
        $statements = [];

        for ($index = $this->random->getInt(1, 3); $index > 0; $index--) {
            $statement = ['effect' => $this->pick(['allow', 'allow', 'deny']), 'actions' => [$this->pick([...self::ACTIONS, 'posts:*', '*'])], ...$this->conditions()];

            if ($this->random->getInt(0, 2) === 0) {
                $statement['resources'] = [$this->pick(['*', (new TenantScopedPost)->getMorphClass() . ':*', (new ScopedPost)->getMorphClass() . ':*', 'posts:*'])];
            }

            if ($isResourcePolicy && $statement['effect'] === 'allow') {
                $role                    = 'role:' . ($this->roles === [] ? 'none' : $this->pick($this->roles));
                $statement['principals'] = [$this->pick([$this->user->getMorphClass() . ':u1', $this->user->getMorphClass() . ':u2', $role])];
            }

            $statements[] = $statement;
        }

        return $statements;
    }

    /**
     * Return a statement's conditions over the resource's status, the caller's
     * input, the subject, the clock or an authentication requirement; or none.
     *
     * @return array<string, mixed>
     */
    private function conditions(): array
    {
        $at = Carbon::parse(self::NOW)->addMinutes($this->pick([-5, 5]))->utc()->format('Y-m-d\TH:i:s\Z');

        return $this->pick([
            [],
            [],
            ['conditions' => ['eq' => ['resource.status' => 'published']]],
            ['conditions' => ['eq_if_exists' => ['resource.status' => 'draft']]],
            ['conditions' => ['eq' => ['input.flag' => 'on']]],
            ['conditions' => ['eq_if_exists' => ['input.flag' => 'off']]],
            ['conditions' => ['eq' => ['subject.id' => $this->pick(['u1', 'u2'])]]],
            ['conditions' => [$this->pick(['before', 'after']) => ['environment.time' => $at]]],
            ['conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]]],
        ]);
    }

    /**
     * Return one of the values, drawn from the seed.
     *
     * @template TValue
     *
     * @param  non-empty-list<TValue>  $values
     * @return TValue
     */
    private function pick(array $values): mixed
    {
        return $values[$this->random->getInt(0, \count($values) - 1)];
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
     * Return a tenant's name for the log.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return string
     */
    private static function nameOf(?StubTenant $tenant): string
    {
        return $tenant === null ? 'the platform' : 'tenant ' . self::keyOf($tenant);
    }
}
