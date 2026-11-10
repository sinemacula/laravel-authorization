<?php

declare(strict_types = 1);

namespace Tests\Integration\BulkChecks;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Random\Engine\Mt19937;
use Random\Randomizer;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\BulkStatusAttributes;
use Tests\Fixtures\BulkChecks\GuardedPost;
use Tests\Fixtures\BulkChecks\GuardedStatusAttributes;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\TenantScopedPost;

/**
 * One random scenario of the bulk check parity property: the subject's grants,
 * roles, policies, boundary, guardrail and the policies attached to the posts'
 * type and records, the request's tenant, application and session, the manager
 * the checks run through and a batch of checks, drawn from a seed: a flat
 * tenant tree or a closure table, grants that reach a tenant's subtree or not,
 * for an application or every one, live or expired, roles through a parent,
 * resource attributes read in bulk or one at a time, some through the tenant
 * scope, so they are found only in the scope a post is decided in, posts of the
 * active tenant, below it, outside it or of none, named by model, by a model
 * holding other attributes in memory, by pair, by reference, by type, by an
 * opaque string, unsaved or not at all, under sparse and string keys, with
 * repeats. Every choice is logged, so a failure names the scenario.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class ParityScenario
{
    /** @var list<string> The actions a scenario checks and grants. */
    private const array ACTIONS = ['posts:view', 'posts:edit'];

    /** @var list<string> The statuses a post may have. */
    private const array STATUSES = ['published', 'draft'];

    /** @var string The instant every scenario starts at. */
    private const string START = '2026-06-01 12:00:00';

    /** @var list<string> What happened, in order. */
    public array $log = [];

    /** @var \SineMacula\Laravel\Authorization\AuthorizationManager The manager the checks run through. */
    public AuthorizationManager $manager;

    /** @var \Random\Randomizer Draws every choice from the seed. */
    private readonly Randomizer $random;

    /** @var list<\Tests\Feature\Stubs\StubTenant|null> The tenants a grant or a post may be in. */
    private array $tenants = [];

    /** @var list<string> The keys of the roles created. */
    private array $roles = [];

    /** @var list<\Illuminate\Database\Eloquent\Model> The posts created. */
    private array $posts = [];

    /** @var \Tests\Feature\Stubs\StubIdentity The subject. */
    private StubIdentity $user;

    /** @var \Tests\Feature\Stubs\StubTenant|null The request's tenant. */
    private ?StubTenant $active = null;

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
        $this->random  = new Randomizer(new Mt19937($seed));
        $this->user    = StubIdentity::create(['id' => 'u1']);
        $this->manager = $app->make(AuthorizationManager::class);
    }

    /**
     * Build the scenario's state: the request, the grants and policies, the
     * posts and their attachments, and the manager.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function build(): void
    {
        Carbon::setTestNow(Carbon::parse(self::START));

        $this->request();
        $this->grants();
        $this->policies();
        $this->posts();
        $this->attachments();
        $this->providers();

        // Live grants expire a day on, the expiring ones ten minutes on.
        Carbon::setTestNow(Carbon::parse(self::START)->addMinutes(20));

        $this->managerOf();
    }

    /**
     * Draw a batch of checks: sparse integer keys or string keys, each check on
     * a post named one way or another, or on no post, with or without the
     * caller's input, some repeated.
     *
     * @return array<array-key, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>
     */
    public function batch(): array
    {
        $checks = [];
        $isText = $this->random->getInt(0, 1) === 1;
        $key    = 0;

        for ($index = $this->random->getInt(1, 12); $index > 0; $index--) {
            $key += $this->random->getInt(1, 3);
            $action   = $this->pick([...self::ACTIONS, ...self::ACTIONS, PackagePermissions::GUARDRAIL_MANAGE]);
            $resource = $this->resource();
            $context  = $this->pick([[], ['flag' => 'on']]);
            $check    = new CheckInput($action, $resource, $context);

            $checks[$isText ? "check-{$key}" : $key] = $check;

            if ($this->random->getInt(0, 4) !== 0) {
                continue;
            }

            $checks[$isText ? "again-{$key}" : ++$key] = $check;
        }

        $describe    = fn (int|string $key, CheckInput $check): string => "{$key} {$check->action} " . $this->describe($check->resource);
        $this->log[] = 'batch: ' . \implode(', ', \array_map($describe, \array_keys($checks), $checks));

        return $checks;
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

        $this->tree($tenants);

        $active       = $this->pick([...$this->tenants, $tenants[0]]);
        $this->active = $active;
        $application  = $this->pick([null, 'admin']);
        $session      = $this->pick([null, 'session-1']);
        $isMet        = $this->random->getInt(0, 1) === 1;

        $this->app->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($this->user, $this->user, $active, $application, null, $session)));
        $this->app->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker($isMet));

        $this->log[] = 'tenant ' . self::nameOf($active) . ', application ' . ($application ?? 'none') . ', session ' . ($session ?? 'none');
        $this->log[] = 'requirements ' . ($isMet ? 'met' : 'unmet');
    }

    /**
     * Bind the tenant tree: the flat one, or a closure table in which the first
     * organisation is above an account, itself above a sub-account, beside a
     * second organisation.
     *
     * @param  list<\Tests\Feature\Stubs\StubTenant>  $tenants
     * @return void
     */
    private function tree(array $tenants): void
    {
        $isClosure = $this->random->getInt(0, 2) > 0;

        $this->app->instance(TenantTree::class, $isClosure ? new ClosureTenantTree : new FlatTenantTree);

        $this->log[] = $isClosure ? 'closure tree' : 'flat tree';

        if (!$isClosure) {
            return;
        }

        [$o1, $a1, $s1, $o2] = \array_map(Reference::of(...), $tenants);

        ClosureTenantTree::add($o1);
        ClosureTenantTree::add($a1, $o1);
        ClosureTenantTree::add($s1, $a1);
        ClosureTenantTree::add($o2);
    }

    /**
     * Grant the subject permissions and roles, each in a tenant or the
     * platform, for an application or every one, live or expired, some roles
     * through a parent.
     *
     * @return void
     */
    private function grants(): void
    {
        for ($index = $this->random->getInt(1, 3); $index > 0; $index--) {
            $permission = Permission::query()->firstOrCreate(['name' => $this->pick([...self::ACTIONS, 'posts:*', PackagePermissions::GUARDRAIL_MANAGE])]);
            $tenant     = $this->pick($this->tenants);
            $expiry     = $this->pick([null, null, Carbon::parse(self::START)->addDay(), Carbon::parse(self::START)->addMinutes(10)]);
            $app        = $this->pick([null, null, 'admin', 'mobile']);
            $kind       = $this->pick(['permission', 'role', 'inherited-role']);
            $isSubtree  = $this->random->getInt(0, 2) > 0;

            $reach       = ($isSubtree ? ' and below' : ' alone') . ' for ' . ($app ?? 'every application');
            $this->log[] = "grant {$kind} {$permission->name} in " . self::nameOf($tenant) . $reach . ($expiry === null ? '' : ' until ' . $expiry->format('H:i'));

            if ($kind === 'permission') {
                $this->user->givePermission($permission, $expiry, $tenant, $isSubtree, $app);

                continue;
            }

            $holder = Role::create(['name' => 'role-' . $index]);
            $role   = $kind === 'role' ? $holder : Role::create(['name' => 'child-' . $index, 'parent_id' => $holder->id]);

            $holder->givePermission($permission);
            $this->user->assignRole($role, $expiry, $tenant, $isSubtree, $app);

            $this->roles[] = $role->id;
        }
    }

    /**
     * Attach the subject's policies, one allowing a post by its status often,
     * and set a boundary and a guardrail, each sometimes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function policies(): void
    {
        // Often an allow that reads each post's status, in the request's tenant
        // and below, so the posts of several scopes read their attributes in
        // one batch.
        if ($this->random->getInt(0, 1) === 1) {
            $tenant = $this->active;

            $this->log[] = 'status policy in ' . self::nameOf($tenant) . ' and below';

            $published = ['effect' => 'allow', 'actions' => [self::ACTIONS[0]], 'conditions' => ['eq' => ['resource.status' => 'published']]];

            $this->user->attachPolicy($this->policy('status', [$published]), null, $tenant, true);
        }

        for ($index = $this->random->getInt(0, 2); $index > 0; $index--) {
            $tenant = $this->pick($this->tenants);

            $this->log[] = 'identity policy in ' . self::nameOf($tenant);

            $policy = $this->policy('identity-' . $index, $this->statements(false));

            $this->user->attachPolicy($policy, null, $tenant, $this->random->getInt(0, 2) > 0);
        }

        if ($this->random->getInt(0, 3) === 0) {
            app(BoundaryService::class)->set($this->user, $this->policy('boundary', $this->capStatements()));
        }

        if ($this->random->getInt(0, 3) !== 0) {
            return;
        }

        $admin  = StubIdentity::create(['id' => 'guardrail-admin']);
        $tenant = $this->pick($this->tenants);

        $admin->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        app(GuardrailService::class)->set($this->policy('guardrail', $this->capStatements()), $tenant, ActingContext::for($admin));

        $this->log[] = 'guardrail in ' . self::nameOf($tenant);
    }

    /**
     * Create the posts: tenantless ones, and tenant-owned ones of every tenant
     * or none, some read through the tenant scope, each published or a draft.
     *
     * @return void
     */
    private function posts(): void
    {
        for ($index = $this->random->getInt(2, 6); $index > 0; $index--) {
            $tenant = $this->pick($this->tenants);
            $status = $this->pick(self::STATUSES);
            $kind   = $this->pick(['owned', 'owned', 'guarded', 'guarded', 'tenantless']);
            $owner  = ['title' => 'p', 'status' => $status, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()];

            $this->posts[] = match ($kind) {
                'owned'   => TenantScopedPost::query()->create($owner),
                'guarded' => GuardedPost::query()->create($owner),
                default   => ScopedPost::query()->create(['title' => 'p', 'status' => $status]),
            };

            $this->log[] = ($kind === 'tenantless' ? 'tenantless post' : "{$kind} post in " . self::nameOf($tenant)) . ", {$status}";
        }
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
        for ($index = $this->random->getInt(0, 4); $index > 0; $index--) {
            $post      = $this->pick($this->posts);
            $tenant    = $this->pick($this->tenants);
            $isSubtree = $this->random->getInt(0, 2) > 0;
            $app       = $this->pick([null, null, 'admin']);
            $isRecord  = $this->random->getInt(0, 1) === 1;
            $target    = $isRecord ? [$post::class, self::keyOf($post)] : $post::class;
            $reach     = ($isSubtree ? ' and below' : ' alone') . ' for ' . ($app ?? 'every application');

            $this->log[] = 'attached to ' . ($isRecord ? 'post ' . self::keyOf($post) : $post::class) . ' in ' . self::nameOf($tenant) . $reach;

            $policy = $this->policy('resource-' . $index, $this->statements(true));

            app(ResourcePolicyService::class)->attach($policy, $target, $tenant, $isSubtree, $app);
        }
    }

    /**
     * Register the posts' attribute providers, reading in bulk or one record at
     * a time, failing for a post sometimes, and the resolver of the tenants of
     * the notes, which no model declares: a fixed tenant, none or none it can
     * tell, asked about each note on its own.
     *
     * @return void
     */
    private function providers(): void
    {
        $providers = [];

        foreach ([ScopedPost::class, TenantScopedPost::class] as $class) {
            $provider = $this->random->getInt(0, 1) === 1 ? new BulkStatusAttributes : new StatusAttributes;

            if ($this->random->getInt(0, 5) === 0) {
                $provider->failing = [self::keyOf($this->pick($this->posts))];
            }

            $this->app->instance($provider::class, $provider);
            $providers[(new $class)->getMorphClass()] = $provider::class;

            $this->log[] = "{$class} attributes " . $provider::class . ' failing ' . \json_encode($provider->failing);
        }

        // Read through the tenant scope, so a post's status is found only in
        // the scope its own check is decided in.
        $this->app->instance(GuardedStatusAttributes::class, new GuardedStatusAttributes);

        $providers[(new GuardedPost)->getMorphClass()] = GuardedStatusAttributes::class;

        // One provider class serves both types when both draw the same one.
        app(ConfigRepository::class)->set('authorization.attributes.resources', $providers);

        $tenant = $this->pick([...$this->tenants, false]);

        $noted = $tenant instanceof StubTenant ? Reference::of($tenant) : $tenant;

        $this->app->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new FixedResourceTenantResolver(null, $noted)));

        $this->log[] = 'notes in ' . ($tenant === false ? 'no tenant it can tell' : self::nameOf($tenant));
    }

    /**
     * Choose the manager the checks run through: the current one, or a clone
     * for the subject, its user, a policy override or a cap.
     *
     * @return void
     */
    private function managerOf(): void
    {
        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app->make(AuthorizationManager::class);
        $choice  = $this->pick(['current', 'current', 'for', 'forUser', 'withPolicies', 'capped']);

        $this->manager = match ($choice) {
            'for'          => $manager->for($this->user),
            'forUser'      => $manager->forUser($this->user),
            'withPolicies' => $manager->withPolicies([$this->override()]),
            'capped'       => $manager->capped([$this->pick(['posts:*', 'posts:view', 'other:*'])]),
            default        => $manager,
        };

        $this->log[] = "manager {$choice}";
    }

    /**
     * Return a policy override, attached to the owned posts' type or to
     * nothing.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private function override(): EvaluationPolicy
    {
        $policy = EvaluationPolicy::fromArray(['name' => 'override', 'statements' => $this->statements(true)]);

        return $policy->withResource($this->pick([null, (new TenantScopedPost)->getMorphClass() . ':*']));
    }

    /**
     * Return the resource of one check: a post by model, by a model holding
     * another status in memory, by pair or by reference, its type, an opaque
     * string, an unsaved post with a key or without one, a note no model
     * declares, a post that does not exist, or no resource.
     *
     * @return mixed
     */
    private function resource(): mixed
    {
        $post = $this->pick($this->posts);
        $id   = self::keyOf($post);

        $named = [
            'pair'      => [$post::class, $id],
            'reference' => ResourceReference::record($post->getMorphClass(), $id),
            'type'      => $post::class,
            'opaque'    => 'posts:' . $id,
            'note'      => ['notes', 'n' . $id],
            'missing'   => [$post::class, '424242'],
            'none'      => null,
        ];

        return match ($kind = $this->pick(['model', 'model', 'fresh', 'fresh', 'pair', 'pair', 'reference', 'type', 'opaque', 'unsaved', 'keyed', 'note', 'missing', 'none'])) {
            'model'   => $post,
            'fresh'   => $this->fresh($post),
            'unsaved' => new TenantScopedPost(['status' => 'published']),
            'keyed'   => self::unsavedLike($post),
            default   => $named[$kind],
        };
    }

    /**
     * Return an unsaved post of the post's tenant given a key no record has.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $post
     * @return \Tests\Fixtures\QueryScoping\TenantScopedPost
     */
    private static function unsavedLike(Model $post): TenantScopedPost
    {
        $unsaved = new TenantScopedPost(['status' => 'published', 'tenant_type' => $post->getAttribute('tenant_type'), 'tenant_id' => $post->getAttribute('tenant_id')]);

        $unsaved->setAttribute('id', 9000);

        return $unsaved;
    }

    /**
     * Return the post loaded afresh, holding the other status in memory.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $post
     * @return \Illuminate\Database\Eloquent\Model
     */
    private function fresh(Model $post): Model
    {
        $fresh = $post->newQueryWithoutScopes()->whereKey($post->getKey())->firstOrFail();

        $fresh->setAttribute('status', $post->getAttribute('status') === 'published' ? 'draft' : 'published');

        return $fresh;
    }

    /**
     * Describe a check's resource for the log.
     *
     * @param  mixed  $resource
     * @return string
     */
    private function describe(mixed $resource): string
    {
        if (!$resource instanceof Model) {
            return $resource instanceof ResourceReference ? 'reference ' . $resource->identifier : (\json_encode($resource) ?: 'resource');
        }

        return \class_basename($resource) . ':' . \json_encode($resource->getKey()) . ($resource->exists ? '' : ' unsaved') . ' ' . \json_encode($resource->getAttribute('status'));
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
            $types     = [(new TenantScopedPost)->getMorphClass() . ':*', (new ScopedPost)->getMorphClass() . ':*', (new GuardedPost)->getMorphClass() . ':*'];

            if ($this->random->getInt(0, 2) === 0) {
                $statement['resources'] = [$this->pick(['*', ...$types, 'notes:*'])];
            }

            if ($isResourcePolicy && $statement['effect'] === 'allow') {
                $statement['principals'] = [$this->pick([$this->user->getMorphClass() . ':u1', $this->user->getMorphClass() . ':u2', $this->roleSelector()])];
            }

            $statements[] = $statement;
        }

        return $statements;
    }

    /**
     * Return a selector naming one of the roles created, or none.
     *
     * @return string
     */
    private function roleSelector(): string
    {
        return 'role:' . ($this->roles === [] ? 'none' : $this->pick($this->roles));
    }

    /**
     * Return a cap's statements: an allow of every action, the posts' or one,
     * with conditions as any statement's.
     *
     * @return list<array<string, mixed>>
     */
    private function capStatements(): array
    {
        return [['effect' => 'allow', 'actions' => [$this->pick(['*', 'posts:*', 'posts:view'])], ...$this->conditions()]];
    }

    /**
     * Return a statement's conditions over the resource's status, the caller's
     * input, the subject, the clock or an authentication requirement; or none.
     *
     * @return array<string, mixed>
     */
    private function conditions(): array
    {
        $at = Carbon::parse(self::START)->addMinutes($this->pick([15, 25]))->utc()->format('Y-m-d\TH:i:s\Z');

        return $this->pick([
            [],
            [],
            ['conditions' => ['eq' => ['resource.status' => 'published']]],
            ['conditions' => ['eq' => ['resource.status' => 'published']]],
            ['conditions' => ['eq_if_exists' => ['resource.status' => 'draft']]],
            ['conditions' => ['eq_if_exists' => ['resource.status' => 'draft']]],
            ['conditions' => ['eq' => ['input.flag' => 'on']]],
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
     * @param  list<TValue>  $values
     * @return TValue
     *
     * @throws \LogicException
     */
    private function pick(array $values): mixed
    {
        if ($values === []) {
            throw new \LogicException('There is nothing to pick from.');
        }

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
