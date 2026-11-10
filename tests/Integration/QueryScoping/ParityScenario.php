<?php

declare(strict_types = 1);

namespace Tests\Integration\QueryScoping;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Random\Engine\Mt19937;
use Random\Randomizer;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
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
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\GuardedPost;
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\Fixtures\QueryScoping\KeyedPost;
use Tests\Fixtures\QueryScoping\NumberedTenantPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\TenantScopedDocument;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\Fixtures\QueryScoping\UuidScopedDocument;

/**
 * One random scenario of the query scoping parity property: a model, its rows,
 * the subject's grants, policies, boundaries, guardrails and resource policies,
 * the request's tenant, application and session, the manager the query is
 * scoped through, the caller's context and the query itself, drawn from a seed
 * within the constructs this release compiles: a flat tenant tree or a closure
 * table of organisations, accounts and sub-accounts, grants that reach a
 * tenant's subtree or not, for an application or every one, live or expired,
 * platform-wide grants, policies attached to the type and to records, and
 * resource patterns naming records by their key or the start of it. A model may
 * scope itself, through the model-level scope. Every choice is logged, so a
 * failure names the scenario.
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
    /** @var list<class-string<\Illuminate\Database\Eloquent\Model>> The models a scenario queries. */
    private const array MODELS = [
        ScopedPost::class, ScopedDocument::class, TenantScopedPost::class, TenantScopedDocument::class,
        ScopedTicket::class, NumberedTenantPost::class, KeyedPost::class, GuardedPost::class,
    ];

    /** @var list<string> The string keys a document may have, and a pattern name, a long key's start included. */
    private const array STRING_KEYS = ['abc', 'ABC', 'abc ', ' abc', 'ábc', "e\u{0301}", '*', 'x:*', 'a\b', 'kkkkk'];

    /** @var list<string> The given integer keys a keyed post may have: zero, negatives and the edges of 64 bits. */
    private const array INTEGER_KEYS = ['0', '-1', '1', '2', '7', '42', '-9223372036854775808', '9223372036854775807'];

    /** @var list<string> The uuid keys a uuid document may have. */
    private const array UUID_KEYS = ['0b1d2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d', 'a0000000-0000-4000-8000-000000000001', 'ffffffff-ffff-4fff-bfff-ffffffffffff'];

    /** @var list<string> Integer ids no record can have, as PHP reads keys. */
    private const array NON_CANONICAL = ['-0', '+1', '01', '1.0', ' 1'];

    /** @var list<string> The actions a scenario scopes to and grants. */
    private const array ACTIONS = ['posts:view', 'posts:edit'];

    /** @var string The instant every scenario starts at. */
    private const string START = '2026-06-01 12:00:00';

    /** @var list<string> What happened, in order. */
    public array $log = [];

    /** @var class-string<\Illuminate\Database\Eloquent\Model> The model queried. */
    public string $model;

    /** @var string The action the query is scoped to. */
    public string $action;

    /** @var array<string, mixed> The caller's context. */
    public array $context = [];

    /** @var \SineMacula\Laravel\Authorization\AuthorizationManager The manager the query is scoped and checked through. */
    public AuthorizationManager $manager;

    /** @var \Random\Randomizer Draws every choice from the seed. */
    private readonly Randomizer $random;

    /** @var list<object|null> The tenants a grant or a row may be in. */
    private array $tenants = [];

    /** @var list<string> The keys of the roles created. */
    private array $roles = [];

    /** @var bool Whether the tenant tree is the closure table, rather than the flat tree. */
    private bool $isClosure = false;

    /** @var \Tests\Feature\Stubs\StubIdentity The subject. */
    private StubIdentity $user;

    /** @var string The model's morph type. */
    private string $type = '';

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
        $this->model   = $this->pick(DB::connection()->getDriverName() === 'pgsql' ? [...self::MODELS, UuidScopedDocument::class] : self::MODELS);
        $this->action  = $this->model === GuardedPost::class ? GuardedPost::ACTION : $this->pick(self::ACTIONS);
        $this->user    = StubIdentity::create(['id' => 'u1']);
        $this->manager = self::service(AuthorizationManager::class);
    }

    /**
     * Build the scenario's state: the request, the grants and policies, the
     * manager, the context and the rows; with a construct outside this
     * release's subset that a check would weigh, when asked.
     *
     * @param  bool  $isOutside
     * @return void
     *
     * @throws \Throwable
     */
    public function build(bool $isOutside = false): void
    {
        Carbon::setTestNow(Carbon::parse(self::START));

        $this->type = (new $this->model)->getMorphClass();

        StubIdentity::create(['id' => 'u2']);

        // Enough classes for the deepest tree and every anchor admitted.
        self::service(ConfigRepository::class)->set('authorization.query_scoping.max_scopes', 64);

        $this->request();
        $this->grants();
        $this->policies();
        $this->rows();
        $this->recordAttachments();

        if ($isOutside) {
            $this->addOutsideConstruct();
        }

        // Live grants expire a day on, the expiring ones ten minutes on.
        Carbon::setTestNow(Carbon::parse(self::START)->addMinutes(20));

        $this->managerOf($isOutside);
        $this->log[] = "model {$this->model}, action {$this->action}, context " . \json_encode($this->context);
    }

    /**
     * Return a fresh query of the model, with the scenario's constraints,
     * shared by the scoped query and its candidate set; the constraint added
     * after the scope, if any, is applied by `after()`.
     *
     * @return \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>): \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    public function constraints(): \Closure
    {
        $shape = $this->pick(['none', 'where', 'grouped-or', 'top-or', 'raw-or', 'expression-or', 'ordered', 'selected']);

        $this->log[] = "query {$shape}";

        return fn (Builder $query): Builder => match ($shape) {
            'where'         => $query->where('title', 'like', 'a%'),
            'grouped-or'    => $query->where(static fn (Builder $nested): Builder => $nested->where('title', 'a1')->orWhere('title', 'b1')),
            'top-or'        => $query->where('title', 'a1')->orWhere('title', 'b1'),
            'raw-or'        => $query->whereRaw('title = \'a1\' OR title = \'b1\''),
            'expression-or' => $query->where(DB::raw('title = \'a2\' OR title = \'b2\'')),
            'ordered'       => $query->orderBy('title')->orderByDesc($this->identity()),
            'selected'      => $query->select([$this->identity(), 'title']),
            default         => $query,
        };
    }

    /**
     * Return the constraint the scenario adds after the scope, if any.
     *
     * @return \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>): \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    public function after(): \Closure
    {
        $isOr = $this->random->getInt(0, 3) === 0;

        $this->log[] = $isOr ? 'orWhere after the scope' : 'nothing after the scope';

        return static fn (Builder $query): Builder => $isOr ? $query->orWhere('title', 'b2') : $query;
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
     * Return the column that tells the model's rows apart.
     *
     * @return string
     */
    public function identity(): string
    {
        return $this->isDocument() ? 'row_id' : 'id';
    }

    /**
     * Determine whether the model scopes itself, through the model-level scope,
     * rather than through `whereAuthorized()`.
     *
     * @return bool
     */
    public function isModelScoped(): bool
    {
        return $this->model === GuardedPost::class;
    }

    /**
     * Return the model's morph type.
     *
     * @return string
     */
    public function type(): string
    {
        return $this->type;
    }

    /**
     * Add one construct outside this release's subset that a check would weigh,
     * attached to the subject so it is material, and log it. A source not
     * marked `ScopeInvariant` is registered for the one that reads it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function addOutsideConstruct(): void
    {
        $deny       = ['effect' => $this->pick(['allow', 'deny']), 'actions' => ['*']];
        $constructs = [
            'question'           => [...$deny, 'resources' => [$this->type . ':?']],
            'bracket'            => [...$deny, 'resources' => [$this->type . ':[ab]']],
            'inner-star'         => [...$deny, 'resources' => [$this->type . ':*b']],
            'two-stars'          => [...$deny, 'resources' => [$this->type . ':a**']],
            'resource-pattern'   => [...$deny, 'resources' => ['${resource.type}:*']],
            'resource-condition' => [...$deny, 'conditions' => ['eq' => ['resource.title' => 'a1']]],
            'unmarked-source'    => [...$deny, 'conditions' => ['eq' => ['plan.tier' => 'pro']]],
        ];

        if ($this->isIntegerKeyed()) {
            $constructs['beyond-64-bits'] = [...$deny, 'resources' => [$this->type . ':9223372036854775808']];
        }

        $construct = $this->pick(\array_keys($constructs));
        $statement = $constructs[$construct] ?? $deny;

        $this->log[] = "outside construct {$construct}";

        if ($construct === 'unmarked-source') {
            self::service(ConfigRepository::class)->set('authorization.context.sources', [PlanContextSource::class]);
            $this->app->forgetInstance(CheckContextFactory::class);
        }

        $this->user->attachPolicy($this->policy('outside', [$statement]));
    }

    /**
     * Resolve the request: the subject in a tenant, an application and a
     * session, or none of them, with a requirement checker that meets every
     * requirement in a session, or none.
     *
     * @return void
     */
    private function request(): void
    {
        $isTeam          = \in_array($this->model, [ScopedTicket::class, NumberedTenantPost::class], true);
        $this->isClosure = $this->random->getInt(0, 2) > 0;
        $this->tenants   = $isTeam
            ? [null, new Reference('teams', '5'), new Reference('teams', '7'), new Reference('teams', '8'), new Reference('teams', '9')]
            : [null, ...\array_map(static fn (string $id): Model => StubTenant::query()->create(['id' => $id]), ['o1', 'a1', 'a2', 's1', 'o2', 'b1'])];

        $this->tree();

        $active      = $this->pick($isTeam ? [...$this->tenants, new Reference('teams', '05')] : $this->tenants);
        $application = $this->pick([null, 'admin']);
        $session     = $this->pick([null, 'session-1']);
        $isMet       = $this->random->getInt(0, 1) === 1;

        $this->app->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($this->user, $this->user, $active, $application, null, $session)));
        $this->app->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker($isMet));

        $this->log[] = 'tenant ' . self::nameOf($active) . ', application ' . ($application ?? 'none') . ', session ' . ($session ?? 'none');
        $this->log[] = 'requirements ' . ($isMet ? 'met' : 'unmet');
    }

    /**
     * Bind the tenant tree: the flat one, or a closure table in which the first
     * tenant is an organisation above two accounts, the first of them above a
     * sub-account, and the next organisation, a sibling, above an account of
     * its own.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function tree(): void
    {
        $this->app->instance(TenantTree::class, $this->isClosure ? new ClosureTenantTree : new FlatTenantTree);

        $this->log[] = $this->isClosure ? 'closure tree' : 'flat tree';

        if (!$this->isClosure) {
            return;
        }

        /** @var list<\SineMacula\Laravel\Authorization\Support\Reference> $tenants */
        $tenants = \array_map(
            static fn (object $tenant): Reference => Reference::of(self::scopeOf($tenant) ?? throw new \LogicException('A tenant is a model or a reference.')),
            \array_values(\array_filter($this->tenants)),
        );
        $parents = \count($tenants) === 4 ? [null, 0, 1, null] : [null, 0, 0, 1, null, 4];

        foreach ($tenants as $index => $tenant) {
            $parent = $parents[$index];

            ClosureTenantTree::add($tenant, $parent === null ? null : $tenants[$parent]);
        }
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
            $permission = Permission::query()->firstOrCreate(['name' => $this->pick([$this->action, $this->action, ...self::ACTIONS, 'posts:*'])]);
            $tenant     = $this->pick($this->tenants);
            $expiry     = $this->pick([null, null, Carbon::parse(self::START)->addDay(), Carbon::parse(self::START)->addMinutes(10)]);
            $app        = $this->pick([null, null, 'admin', 'mobile']);
            $kind       = $this->pick(['permission', 'role', 'inherited-role']);
            $isSubtree  = $this->random->getInt(0, 2) > 0;

            $until       = $expiry === null ? '' : ' until ' . $expiry->format('H:i');
            $reach       = $isSubtree ? ' and below' : ' alone';
            $this->log[] = "grant {$kind} {$permission->name} in " . self::nameOf($tenant) . $reach . ' for ' . ($app ?? 'every application') . $until;

            if ($kind === 'permission') {
                $this->user->givePermission($permission, $expiry, self::scopeOf($tenant), $isSubtree, $app);

                continue;
            }

            $holder = Role::create(['name' => 'role-' . $index]);
            $role   = $kind === 'role' ? $holder : Role::create(['name' => 'child-' . $index, 'parent_id' => $holder->id]);

            $holder->givePermission($permission);
            $this->user->assignRole($role, $expiry, self::scopeOf($tenant), $isSubtree, $app);

            $this->roles[] = $role->id;
        }
    }

    /**
     * Attach the subject's policies, and set a boundary, a guardrail and the
     * type's resource policies, each sometimes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function policies(): void
    {
        for ($index = $this->random->getInt(0, 2); $index > 0; $index--) {
            $tenant    = $this->pick($this->tenants);
            $isSubtree = $this->random->getInt(0, 2) > 0;

            $this->log[] = 'identity policy in ' . self::nameOf($tenant) . ($isSubtree ? ' and below' : ' alone');

            $this->user->attachPolicy($this->policy('identity-' . $index, $this->statements(false)), null, self::scopeOf($tenant), $isSubtree);
        }

        if ($this->random->getInt(0, 3) === 0) {
            self::service(BoundaryService::class)->set($this->user, $this->policy('boundary', $this->capStatements()));
        }

        if ($this->random->getInt(0, 3) === 0) {
            $this->guardrail();
        }

        for ($index = $this->random->getInt(0, 2); $index > 0; $index--) {
            $tenant    = $this->pick($this->tenants);
            $isSubtree = $this->random->getInt(0, 2) > 0;
            $app       = $this->pick([null, 'admin']);

            $policy = $this->policy('resource-' . $index, $this->statements(true));

            $this->log[] = 'attached to the type in ' . self::nameOf($tenant) . ($isSubtree ? ' and below' : ' alone') . ' for ' . ($app ?? 'every application');

            self::service(ResourcePolicyService::class)->attach($policy, $this->model, self::scopeOf($tenant), $isSubtree, $app);
        }
    }

    /**
     * Set a guardrail on the platform, by an administrator who may.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function guardrail(): void
    {
        $admin = StubIdentity::create(['id' => 'guardrail-admin']);

        $admin->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]));

        $tenant = $this->pick($this->tenants);

        self::service(GuardrailService::class)->set($this->policy('guardrail', $this->capStatements()), self::scopeOf($tenant), ActingContext::for($admin));

        $this->log[] = 'guardrail in ' . self::nameOf($tenant);
    }

    /**
     * Create the model's rows: keys at the edges the guards cover, and tenants
     * none, partial, the active one, another or one too long to read.
     *
     * @return void
     */
    private function rows(): void
    {
        $keys  = [...self::STRING_KEYS, '', null, $this->longKey(1), $this->longKey(0)];
        $keys  = DB::connection()->getDriverName() === 'pgsql' ? $keys : [...$keys, "a\0b"];
        $given = $this->givenKeys();
        $count = $given === [] ? 10 : \count($given);

        for ($index = 0; $index < $count; $index++) {
            $attributes = ['title' => $this->pick(['a1', 'a2', 'b1', 'b2']), ...$this->tenantColumns()];

            if ($this->isDocument()) {
                $attributes['code'] = $this->pick($keys);
            }

            $this->model::query()->create($given === [] ? $attributes : [...$attributes, 'id' => $given[$index]]);
        }
    }

    /**
     * Return the keys the model's records are given, in the order they are
     * created: shuffled integers at the edges for a keyed post, uuids for a
     * uuid document, none for a model whose keys are generated.
     *
     * @return list<int|string>
     */
    private function givenKeys(): array
    {
        $uuids = \array_map(static fn (int $index): string => \sprintf('c0000000-0000-4000-8000-%012d', $index), \range(1, 7));

        return match ($this->model) {
            KeyedPost::class          => \array_map(static fn (string $key): int => (int) $key, $this->random->shuffleArray(self::INTEGER_KEYS)),
            UuidScopedDocument::class => [...self::UUID_KEYS, ...$uuids],
            default                   => [],
        };
    }

    /**
     * Attach policies to some of the model's records, each in a tenant or the
     * platform, reaching its subtree or not, for an application or every one; a
     * key no attachment can name is skipped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function recordAttachments(): void
    {
        for ($index = $this->random->getInt(0, 2); $index > 0; $index--) {
            $key       = $this->pick($this->keys());
            $tenant    = $this->pick($this->tenants);
            $isSubtree = $this->random->getInt(0, 2) > 0;
            $app       = $this->pick([null, null, 'admin']);
            $policy    = $this->policy('record-' . $index, $this->statements(true));

            $reach       = $isSubtree ? ' and below' : ' alone';
            $this->log[] = 'attached to record ' . \json_encode($key) . ' in ' . self::nameOf($tenant) . $reach . ' for ' . ($app ?? 'every application');

            try {
                self::service(ResourcePolicyService::class)->attach($policy, [$this->model, $key], self::scopeOf($tenant), $isSubtree, $app);
            } catch (\InvalidArgumentException) {
                $this->log[] = 'the key cannot be attached to';
            }
        }
    }

    /**
     * Return the keys a pattern or an attachment may name: the keys the model's
     * records may have, and ids no record can have.
     *
     * @return non-empty-list<string>
     */
    private function keys(): array
    {
        return match (true) {
            $this->isDocument()                        => self::STRING_KEYS,
            $this->model === KeyedPost::class          => [...self::INTEGER_KEYS, ...self::NON_CANONICAL],
            $this->model === UuidScopedDocument::class => [...self::UUID_KEYS, \strtoupper(self::UUID_KEYS[0]), 'not-a-uuid'],
            default                                    => ['1', '2', '3', '5', '10', ...self::NON_CANONICAL],
        };
    }

    /**
     * Determine whether the model's key is an integer.
     *
     * @return bool
     */
    private function isIntegerKeyed(): bool
    {
        return !$this->isDocument() && $this->model !== UuidScopedDocument::class;
    }

    /**
     * Determine whether the model is a document, keyed by a string that is not
     * its table's primary key.
     *
     * @return bool
     */
    private function isDocument(): bool
    {
        return \in_array($this->model, [ScopedDocument::class, TenantScopedDocument::class], true);
    }

    /**
     * Return the tenant columns of a new row.
     *
     * @return array<string, mixed>
     */
    private function tenantColumns(): array
    {
        if ($this->model === ScopedTicket::class) {
            return ['team_id' => $this->pick([null, 5, 7, 0])];
        }

        if ($this->model === NumberedTenantPost::class) {
            return self::numberedTenantColumns($this->pick([[null, null], ['teams', 5], ['teams', 7], [null, 5], ['teams', null], ['other', 5], [null, 1.5], ['teams', 1e20]]));
        }

        $tenant = $this->pick($this->tenants);
        $type   = (new StubTenant)->getMorphClass();

        return $this->pick([
            ['tenant_type' => null, 'tenant_id' => null],
            ['tenant_type' => $tenant === null ? null : $type, 'tenant_id' => $tenant instanceof Model ? $tenant->getKey() : null],
            ['tenant_type' => null, 'tenant_id' => 't1'],
            ['tenant_type' => $type, 'tenant_id' => null],
            ['tenant_type' => 'other', 'tenant_id' => 't1'],
            ['tenant_type' => $type, 'tenant_id' => \str_repeat('t', 200)],
        ]);
    }

    /**
     * Return the tenant columns of a new numbered post: a real number, which
     * SQLite alone keeps in an integer column, is kept as none elsewhere.
     *
     * @param  array{string|null, float|int|null}  $tenant
     * @return array<string, mixed>
     */
    private static function numberedTenantColumns(array $tenant): array
    {
        [$type, $id] = $tenant;

        return ['tenant_type' => $type, 'tenant_id' => \is_float($id) && DB::connection()->getDriverName() !== 'sqlite' ? null : $id];
    }

    /**
     * Return a key whose identifier is `PHP_MAXPATHLEN` bytes less the given
     * margin, so one with no margin is too long for `fnmatch()` and one with a
     * margin of a byte is not.
     *
     * @param  int  $margin
     * @return string
     */
    private function longKey(int $margin): string
    {
        return \str_repeat('k', \PHP_MAXPATHLEN - \strlen($this->type) - 1 - $margin);
    }

    /**
     * Choose the manager the query is scoped through: the current one, or a
     * clone for the subject, its user, a policy override or a cap; never an
     * override when a construct outside the subset is to be weighed, since it
     * replaces the policies that hold it.
     *
     * @param  bool  $isOutside
     * @return void
     */
    private function managerOf(bool $isOutside): void
    {
        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app->make(AuthorizationManager::class);
        $choice  = $this->isModelScoped() ? 'current' : $this->pick($isOutside ? ['current', 'for', 'forUser', 'capped'] : ['current', 'for', 'forUser', 'withPolicies', 'capped']);
        $user    = $this->user;

        $this->manager = match ($choice) {
            'for'          => $manager->for($user),
            'forUser'      => $manager->forUser($user),
            'withPolicies' => $manager->withPolicies([$this->override()]),
            'capped'       => $manager->capped([$this->pick(['posts:*', 'posts:view', 'other:*'])]),
            default        => $manager,
        };

        $this->context = $this->isModelScoped() ? [] : $this->pick([
            [], ['flag'                                                   => 'on'], ['flag' => 'off'], ['t' => $this->type],
            ['t' => $this->type, 'k' => $this->pick($this->keys())], ['k' => '*'], ['k' => 'x:*'], ['k' => $this->pick($this->keys())],
        ]);
        $this->log[] = "manager {$choice}";
    }

    /**
     * Return a policy override, attached to the type or to nothing.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private function override(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'override', 'statements' => $this->statements(true)])->withResource($this->pick([null, $this->type . ':*']));
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
     * Return one to three statements within this release's subset, an allow
     * naming its principals when it is a resource policy's.
     *
     * @param  bool  $isResourcePolicy
     * @return list<array<string, mixed>>
     */
    private function statements(bool $isResourcePolicy): array
    {
        $statements = [];

        for ($index = $this->random->getInt(1, 3); $index > 0; $index--) {
            $statement = ['effect' => $this->pick(['allow', 'allow', 'allow', 'deny'])];
            $statement = [...$statement, ...$this->targets(), ...$this->conditions()];

            if ($isResourcePolicy && $statement['effect'] === 'allow') {
                $role                    = 'role:' . ($this->roles === [] ? 'none' : $this->pick($this->roles));
                $statement['principals'] = [$this->pick([$this->user->getMorphClass() . ':u1', $this->user->getMorphClass() . ':u2', $role])];
            }

            $statements[] = $statement;
        }

        return $statements;
    }

    /**
     * Return a cap's statements: mostly an allow of every action, with
     * resources and conditions as any statement's, and then some more.
     *
     * @return list<array<string, mixed>>
     */
    private function capStatements(): array
    {
        $resources = $this->pick([[], ['resources' => ['*']], ['resources' => [$this->type . ':*']]]);
        $first     = ['effect' => 'allow', 'actions' => [$this->pick(['*', 'posts:*', 'posts:view'])], ...$resources, ...$this->conditions()];

        return [$first, ...($this->random->getInt(0, 2) === 0 ? $this->statements(false) : [])];
    }

    /**
     * Return a statement's actions and resources, each over the whole type.
     *
     * @return array<string, list<string>>
     */
    private function targets(): array
    {
        $actions = $this->random->getInt(0, 5) === 0
            ? ['not_actions' => [$this->pick(['posts:edit', 'posts:view', 'other:*'])]]
            : ['actions' => [$this->pick([...self::ACTIONS, 'posts:*', '*'])]];

        $prefix = \substr($this->type . ':', 0, $this->random->getInt(0, \strlen($this->type) + 1)) . '*';
        // A document's backslashes are literal; a star, a question mark or a
        // bracket is literal only once substituted, so a key holding one is
        // named through the caller's input.
        $key       = $this->pick($this->keys());
        $literal   = $this->type . ':' . $key;
        $start     = $this->type . ':' . \explode('*', \mb_substr($key, 0, $this->random->getInt(1, \max(1, \mb_strlen($key)))))[0] . '*';
        $resources = $this->pick([
            [],
            ['resources' => ['*']],
            ['resources' => [$this->type . ':*']],
            ['resources' => [$prefix]],
            ['resources' => [$prefix, '*']],
            ['resources' => ['${input.t}:*']],
            ['not_resources' => [$prefix]],
            ['not_resources' => [$this->type . ':*']],
            ['resources' => [$literal]],
            ['resources' => [$literal]],
            ['resources' => [$start]],
            ['resources' => [$start, $literal]],
            ['not_resources' => [$literal]],
            ['not_resources' => [$start]],
            ['resources' => [$this->type . ':${input.k}']],
            ['resources' => ['${input.t}:${input.k}']],
            ['not_resources' => [$this->type . ':${input.k}']],
            ['resources' => ['${input.t}:${input.k}*']],
            ['resources' => ['other:' . $key]],
        ]);

        return [...$actions, ...$resources];
    }

    /**
     * Return a statement's conditions over what this release folds: the
     * caller's input, the subject's built-in keys, the frozen clock and an
     * authentication requirement; or none.
     *
     * @return array<string, mixed>
     */
    private function conditions(): array
    {
        $at = Carbon::parse(self::START)->addMinutes($this->pick([15, 25]))->utc()->format('Y-m-d\TH:i:s\Z');

        return $this->pick([
            [],
            [],
            ['conditions' => ['eq' => ['input.flag' => 'on']]],
            ['conditions' => ['eq_if_exists' => ['input.missing' => 'x']]],
            ['conditions' => ['null' => ['input.absent' => true]]],
            ['conditions' => ['eq' => ['subject.id' => $this->pick(['u1', 'u2'])]]],
            ['conditions' => ['eq' => ['subject.tenant.id' => 't1']]],
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
     * Return a tenant's name for the log.
     *
     * @param  object|null  $tenant
     * @return string
     */
    private static function nameOf(?object $tenant): string
    {
        return match (true) {
            $tenant instanceof Reference => "{$tenant->type}:{$tenant->id}",
            $tenant instanceof Model     => 'tenant ' . $tenant->getKey(), // @phpstan-ignore binaryOp.invalid
            default                      => 'the platform',
        };
    }

    /**
     * Return a management service, as the container binds it.
     *
     * @template TService of object
     *
     * @param  class-string<TService>  $class
     * @return TService
     *
     * @throws \LogicException
     */
    private static function service(string $class): object
    {
        $service = app($class);

        return $service instanceof $class ? $service : throw new \LogicException("{$class} is not bound.");
    }

    /**
     * Return the tenant a grant is made in, or null for the platform.
     *
     * @param  object|null  $tenant
     * @return \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function scopeOf(?object $tenant): Model|Reference|null
    {
        return $tenant instanceof Model || $tenant instanceof Reference ? $tenant : null;
    }
}
