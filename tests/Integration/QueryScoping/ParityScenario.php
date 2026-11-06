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
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
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
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\TenantScopedDocument;
use Tests\Fixtures\QueryScoping\TenantScopedPost;

/**
 * One random scenario of the query scoping parity property: a model, its rows,
 * the subject's grants, policies, boundaries, guardrails and resource policies,
 * the request's tenant, application and session, the manager the query is
 * scoped through, the caller's context and the query itself, drawn from a seed
 * within the constructs part 1 compiles. Every choice is logged, so a failure
 * names the scenario.
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
    private const array MODELS = [ScopedPost::class, ScopedDocument::class, TenantScopedPost::class, TenantScopedDocument::class, ScopedTicket::class];

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
        $this->model   = $this->pick(self::MODELS);
        $this->action  = $this->pick(self::ACTIONS);
        $this->user    = StubIdentity::create(['id' => 'u1']);
        $this->manager = self::service(AuthorizationManager::class);
    }

    /**
     * Build the scenario's state: the request, the grants and policies, the
     * manager, the context and the rows; with a construct outside part 1's
     * subset that a check would weigh, when asked.
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

        $this->request();
        $this->grants();
        $this->policies();
        $this->rows();

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
        $shape = $this->pick(['none', 'where', 'grouped-or', 'top-or', 'ordered', 'selected']);

        $this->log[] = "query {$shape}";

        return fn (Builder $query): Builder => match ($shape) {
            'where'      => $query->where('title', 'like', 'a%'),
            'grouped-or' => $query->where(static fn (Builder $nested): Builder => $nested->where('title', 'a1')->orWhere('title', 'b1')),
            'top-or'     => $query->where('title', 'a1')->orWhere('title', 'b1'),
            'ordered'    => $query->orderBy('title')->orderByDesc($this->identity()),
            'selected'   => $query->select([$this->identity(), 'title']),
            default      => $query,
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
        return \in_array($this->model, [ScopedDocument::class, TenantScopedDocument::class], true) ? 'row_id' : 'id';
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
     * Add one construct outside part 1's subset that a check would weigh,
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
            'literal-id'         => [...$deny, 'resources' => [$this->type . ':1']],
            'escaped-star'       => [...$deny, 'resources' => [$this->type . ':\*']],
            'longer-prefix'      => [...$deny, 'resources' => [$this->type . ':4*']],
            'question'           => [...$deny, 'resources' => [$this->type . ':?']],
            'other-type'         => [...$deny, 'resources' => ['other:*']],
            'other-record'       => [...$deny, 'resources' => ['other:5']],
            'resource-pattern'   => [...$deny, 'resources' => ['${resource.type}:*']],
            'resource-condition' => [...$deny, 'conditions' => ['eq' => ['resource.title' => 'a1']]],
            'unmarked-source'    => [...$deny, 'conditions' => ['eq' => ['plan.tier' => 'pro']]],
            'record-attachment'  => ['effect' => 'deny', 'actions' => ['*']],
        ];
        $construct = $this->pick(\array_keys($constructs));
        $statement = $constructs[$construct];

        $this->log[] = "outside construct {$construct}";

        if ($construct === 'unmarked-source') {
            self::service(ConfigRepository::class)->set('authorization.context.sources', [PlanContextSource::class]);
            $this->app->forgetInstance(CheckContextFactory::class);
        }

        if ($construct === 'record-attachment') {
            self::service(ResourcePolicyService::class)->attach($this->policy('record', [$statement]), [$this->model, '1']);

            return;
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
        $isTeam        = $this->model === ScopedTicket::class;
        $this->tenants = $isTeam
            ? [null, new Reference('teams', '5'), new Reference('teams', '7')]
            : [null, StubTenant::query()->create(['id' => 't1']), StubTenant::query()->create(['id' => 't2'])];

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

            $until       = $expiry === null ? '' : ' until ' . $expiry->format('H:i');
            $this->log[] = "grant {$kind} {$permission->name} in " . self::nameOf($tenant) . ' for ' . ($app ?? 'every application') . $until;

            if ($kind === 'permission') {
                $this->user->givePermission($permission, $expiry, self::scopeOf($tenant), true, $app);

                continue;
            }

            $holder = Role::create(['name' => 'role-' . $index]);
            $role   = $kind === 'role' ? $holder : Role::create(['name' => 'child-' . $index, 'parent_id' => $holder->id]);

            $holder->givePermission($permission);
            $this->user->assignRole($role, $expiry, self::scopeOf($tenant), true, $app);

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
            $tenant = $this->pick($this->tenants);

            $this->user->attachPolicy($this->policy('identity-' . $index, $this->statements(false)), null, self::scopeOf($tenant));
        }

        if ($this->random->getInt(0, 3) === 0) {
            self::service(BoundaryService::class)->set($this->user, $this->policy('boundary', $this->capStatements()));
        }

        if ($this->random->getInt(0, 3) === 0) {
            $this->guardrail();
        }

        for ($index = $this->random->getInt(0, 2); $index > 0; $index--) {
            $tenant = $this->pick($this->tenants);

            $policy = $this->policy('resource-' . $index, $this->statements(true));

            self::service(ResourcePolicyService::class)->attach($policy, $this->model, self::scopeOf($tenant), true, $this->pick([null, 'admin']));
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

        $admin->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAILS_MANAGE]));

        self::service(GuardrailService::class)->set($this->policy('guardrail', $this->capStatements()), null, $admin);

        $this->log[] = 'platform guardrail';
    }

    /**
     * Create the model's rows: keys at the edges the guards cover, and tenants
     * none, partial, the active one, another or one too long to read.
     *
     * @return void
     */
    private function rows(): void
    {
        $keys    = ['abc', 'ABC', 'abc ', ' abc', 'ábc', "e\u{0301}", '*', 'x:*', 'a\b', '', null, $this->longKey(1), $this->longKey(0)];
        $keys    = DB::connection()->getDriverName() === 'pgsql' ? $keys : [...$keys, "a\0b"];
        $isKeyed = \in_array($this->model, [ScopedDocument::class, TenantScopedDocument::class], true);

        for ($index = 0; $index < 10; $index++) {
            $attributes = ['title' => $this->pick(['a1', 'a2', 'b1', 'b2'])];

            if ($isKeyed) {
                $attributes['code'] = $this->pick($keys);
            }

            $this->model::query()->create([...$attributes, ...$this->tenantColumns()]);
        }
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
        $choice  = $this->pick($isOutside ? ['current', 'for', 'forUser', 'capped'] : ['current', 'for', 'forUser', 'withPolicies', 'capped']);
        $user    = $this->user;

        $this->manager = match ($choice) {
            'for'          => $manager->for($user),
            'forUser'      => $manager->forUser($user),
            'withPolicies' => $manager->withPolicies([$this->override()]),
            'capped'       => $manager->capped([$this->pick(['posts:*', 'posts:view', 'other:*'])]),
            default        => $manager,
        };

        $this->context = $this->pick([[], ['flag' => 'on'], ['flag' => 'off'], ['t' => $this->type]]);
        $this->log[]   = "manager {$choice}";
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
     * Return one to three statements within part 1's subset, an allow naming
     * its principals when it is a resource policy's.
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

        $prefix    = \substr($this->type . ':', 0, $this->random->getInt(0, \strlen($this->type) + 1)) . '*';
        $resources = $this->pick([
            [],
            ['resources' => ['*']],
            ['resources' => [$this->type . ':*']],
            ['resources' => [$prefix]],
            ['resources' => [$prefix, '*']],
            ['resources' => ['${input.t}:*']],
            ['not_resources' => [$prefix]],
            ['not_resources' => [$this->type . ':*']],
        ]);

        return [...$actions, ...$resources];
    }

    /**
     * Return a statement's conditions over what part 1 folds: the caller's
     * input, the subject's built-in keys, the frozen clock and an
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
     * @param  non-empty-list<TValue>  $values
     * @return TValue
     */
    private function pick(array $values): mixed
    {
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
