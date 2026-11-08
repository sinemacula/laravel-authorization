<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * One random scenario of the escalation property: tenants in a closure tree,
 * roles with a hierarchy and ranks, permissions (wildcards included), policies
 * with allows and denies attached to roles and subjects, boundaries, a
 * guardrail, a resource policy naming a role or a subject, subjects holding all
 * of these in random scopes, and an actor with random administration rights,
 * random authority of its own and a random rank, who then makes random
 * delegated operations.
 *
 * Everything is drawn from the seed, so a scenario can be replayed from its
 * log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class EscalationScenario
{
    /** @var list<string> The application's actions, as the catalogue declares them. */
    public const array ACTIONS = ['posts:read', 'posts:edit', 'posts:delete', 'comments:read', 'comments:write', 'reports:view'];

    /** @var list<string> The patterns a grant or a statement may name beside the actions. */
    private const array PATTERNS = ['posts:*', 'comments:*', '*:read'];

    /** @var list<string> The actions and patterns a role or a subject holds. */
    private const array HELD = [...self::ACTIONS, ...self::PATTERNS];

    /** @var list<string> The administration rights an actor may be given. */
    private const array RIGHTS = [
        Actions::PERMISSION_GRANT, Actions::PERMISSION_REVOKE, Actions::ROLE_GRANT, Actions::ROLE_REVOKE, Actions::POLICY_ATTACH,
        Actions::POLICY_DETACH, Actions::ROLE_PARENT_SET, Actions::POLICY_UPDATE, Actions::BOUNDARY_SET, Actions::BOUNDARY_REMOVE,
        Actions::ADMINISTRATION_SELF, Actions::ADMINISTRATION_UNBOUNDED,
    ];

    /** @var list<string> The actions, patterns and rights an operation may grant. */
    private const array GRANTABLE = [...self::HELD, ...self::RIGHTS];

    /** @var list<\Tests\Feature\Stubs\StubTenant> The tenants, the first at the top of the tree. */
    public array $tenants = [];

    /** @var list<\SineMacula\Laravel\Authorization\Models\Role> The roles, a parent always before its children. */
    public array $roles = [];

    /** @var list<\SineMacula\Laravel\Authorization\Models\Policy> The managed policies. */
    public array $policies = [];

    /** @var list<\Tests\Feature\Stubs\StubIdentity> The subjects, the actor last. */
    public array $subjects = [];

    /** @var \Tests\Feature\Stubs\StubIdentity The actor's identity. */
    public readonly StubIdentity $actorModel;

    /** @var \SineMacula\Laravel\Authorization\Administration\ActingContext The actor. */
    public readonly ActingContext $actor;

    /** @var bool Whether the actor may grant what it does not hold, through a grantable right. */
    public bool $isGrantable = false;

    /** @var list<string> What the scenario did, for its replay. */
    private array $log = [];

    /** @var \Tests\Integration\Administration\SeededChoices The scenario's random choices. */
    private readonly SeededChoices $random;

    /** @var \SineMacula\Laravel\Authorization\Services\GrantService The grant service. */
    private readonly GrantService $grantService;

    /** @var \SineMacula\Laravel\Authorization\Services\RoleService The role service. */
    private readonly RoleService $roleService;

    /** @var \SineMacula\Laravel\Authorization\Services\PolicyService The policy service. */
    private readonly PolicyService $policyService;

    /** @var \SineMacula\Laravel\Authorization\Services\BoundaryService The boundary service. */
    private readonly BoundaryService $boundaryService;

    /**
     * Create the scenario of the seed, with its actor, who holds nothing yet.
     *
     * @param  int  $seed
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function __construct(

        /** The seed every choice is drawn from. */
        public readonly int $seed,

        /** The application the scenario runs in. */
        private readonly Application $app,
    ) {
        $this->random          = new SeededChoices($seed);
        $this->grantService    = $app->make(GrantService::class);
        $this->roleService     = $app->make(RoleService::class);
        $this->policyService   = $app->make(PolicyService::class);
        $this->boundaryService = $app->make(BoundaryService::class);
        $this->actorModel      = StubIdentity::query()->create(['id' => 'actor']);
        $this->actor           = ActingContext::for($this->actorModel);
    }

    /**
     * Build the scenario's state, every write trusted, the application's
     * actions declared beside the package's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function build(): void
    {
        $definitions = \array_map(static fn (string $action): PermissionDefinition => new PermissionDefinition($action), self::ACTIONS);

        $this->app->instance(DeclaredPermissions::class, new DeclaredPermissions($definitions));
        $this->app->make(ConfigRepository::class)->set('authorization.permission_providers', [DeclaredPermissions::class]);
        $this->app->forgetInstance(PermissionCatalogue::class);

        $this->tree();
        $this->definitions();
        $this->subjectsAndActor();
        $this->boundaries();
        $this->extras();
    }

    /**
     * Return a random delegated operation as the actor: its description, the
     * administration action it is decided under, whether it may lift a
     * boundary, and the call.
     *
     * @return array{string, string, bool, \Closure(): mixed}
     */
    public function operation(): array
    {
        $kind = $this->random->pick(['permission', 'permission', 'role', 'role', 'policy', 'revoke', 'membership', 'parent', 'rewrite', 'boundary', 'unbound']);

        [$description, $action, $call] = match ($kind) {
            'permission', 'role', 'policy'  => $this->grant($kind),
            'revoke', 'boundary', 'unbound' => $this->removal($kind),
            default                         => $this->definition($kind),
        };

        $this->log[] = "operation: {$kind} {$description}";

        return ["{$kind} {$description}", $action, \in_array($kind, ['boundary', 'unbound'], true), $call];
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
     * Return the model's key as a string, or the text given for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @param  string  $none
     * @return string
     */
    public static function key(?Model $model, string $none = ''): string
    {
        $key = $model?->getKey();

        return \is_scalar($key) ? (string) $key : $none;
    }

    /**
     * Return a random grant of the kind as the actor: of a permission, an
     * administration right included, a role or a policy, to a random subject,
     * the actor now and then, in a random scope.
     *
     * @param  string  $kind
     * @return array{string, string, \Closure(): mixed}
     */
    private function grant(string $kind): array
    {
        [$target, $tenant, $below, $where] = $this->place();

        $actor  = $this->actor;
        $grants = $this->grantService;

        return match ($kind) {
            'permission' => [($permission = self::permission($this->random->pick(self::GRANTABLE)))->name . $where, Actions::PERMISSION_GRANT,
                static fn (): mixed => $grants->grantPermission($target, $permission, actor: $actor, tenant: $tenant, includeSubtree: $below)],
            'role' => [($role = $this->random->pick($this->roles))->name . $where, Actions::ROLE_GRANT,
                static fn (): mixed => $grants->grantRole($target, $role, actor: $actor, tenant: $tenant, includeSubtree: $below)],
            default => [($policy = $this->random->pick($this->policies))->name . $where, Actions::POLICY_ATTACH,
                static fn (): mixed => $grants->attachPolicy($target, $policy, actor: $actor, tenant: $tenant, includeSubtree: $below)],
        };
    }

    /**
     * Return a random revocation or boundary change of the kind as the actor.
     *
     * @param  string  $kind
     * @return array{string, string, \Closure(): mixed}
     */
    private function removal(string $kind): array
    {
        [$target, $tenant, $below, $where] = $this->place();

        $actor      = $this->actor;
        $grants     = $this->grantService;
        $boundaries = $this->boundaryService;

        return match ($kind) {
            'revoke' => [($role = $this->random->pick($this->roles))->name . $where, Actions::ROLE_REVOKE,
                static fn (): mixed => $grants->revokeRole($target, $role, $actor, $tenant)],
            'boundary' => [($policy = $this->random->pick($this->policies))->name . $where, Actions::BOUNDARY_SET,
                static fn (): mixed => $boundaries->set($target, $policy, $tenant, $below, $actor)],
            default => [$where, Actions::BOUNDARY_REMOVE,
                static fn (): mixed => $boundaries->remove($target, $tenant, $actor)],
        };
    }

    /**
     * Return a random change to a definition of the kind as the actor: a
     * permission added to a role, a role put under another or none, or a policy
     * rewritten.
     *
     * @param  string  $kind
     * @return array{string, string, \Closure(): mixed}
     */
    private function definition(string $kind): array
    {
        $actor    = $this->actor;
        $role     = $this->random->pick($this->roles);
        $roles    = $this->roleService;
        $policies = $this->policyService;

        return match ($kind) {
            'membership' => [$role->name . ' carries ' . ($permission = self::permission($this->random->pick(self::HELD)))->name, Actions::PERMISSION_GRANT,
                static fn (): mixed => $roles->grantPermission($role, $permission, null, $actor)],
            'parent' => [$role->name . ' under ' . (($parent = $this->parentFor($role))->name ?? 'nothing'), Actions::ROLE_PARENT_SET,
                static fn (): mixed => $roles->setParent($role, $parent, $actor)],
            default => [($policy = $this->random->pick($this->policies))->name . ' as ' . \json_encode($document = $this->document()), Actions::POLICY_UPDATE,
                static fn (): mixed => $policies->rewrite(Policy::query()->whereKey($policy->getKey())->firstOrFail(), $document, $actor)],
        };
    }

    /**
     * Return where a grant goes: a random subject, the actor now and then, a
     * random scope, whether it reaches below, and its description.
     *
     * @return array{\Tests\Feature\Stubs\StubIdentity, \Tests\Feature\Stubs\StubTenant|null, bool, string}
     */
    private function place(): array
    {
        $target = $this->random->isOneIn(5) ? $this->actorModel : $this->random->pick(\array_slice($this->subjects, 0, -1));
        $tenant = $this->scope();
        $below  = !$this->random->isOneIn(3);
        $where  = ' for ' . self::key($target) . ' in ' . ($tenant === null ? 'platform' : 'tenant ' . self::key($tenant)) . ($below ? ' and below' : '');

        return [$target, $tenant, $below, $where];
    }

    /**
     * Build a tree of three or four tenants, each below a random earlier one or
     * at the top.
     *
     * @return void
     */
    private function tree(): void
    {
        $this->app->instance(TenantTree::class, new ClosureTenantTree);

        for ($index = 0, $count = $this->random->between(3, 4); $index < $count; $index++) {
            $tenant = StubTenant::query()->create(['id' => 't' . $index, 'name' => 't' . $index]);
            $parent = $index === 0 || $this->random->isOneIn(4) ? null : $this->random->pick($this->tenants);

            ClosureTenantTree::add(Reference::of($tenant), $parent === null ? null : Reference::of($parent));

            $this->tenants[] = $tenant;
            $this->log[]     = 'tenant ' . self::key($tenant) . ' under ' . self::key($parent, 'nothing');
        }
    }

    /**
     * Create the policies and the roles: a hierarchy, ranks, permissions and
     * policies of their own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function definitions(): void
    {
        for ($index = 0, $count = $this->random->between(2, 4); $index < $count; $index++) {
            $document         = $this->document();
            $this->policies[] = $this->policyService->create('policy-' . $index, $document);
            $this->log[]      = "policy policy-{$index}: " . \json_encode($document);
        }

        for ($index = 0, $count = $this->random->between(3, 5); $index < $count; $index++) {
            $parent = $this->roles === [] || $this->random->isOneIn(2) ? null : $this->random->pick($this->roles);
            $rank   = $this->random->pick([null, null, 2, 3, 5, 8]);
            $role   = Role::query()->create(['name' => 'role-' . $index, 'rank' => $rank, 'parent_id' => $parent?->getKey()]);

            $this->roles[] = $role;
            $this->log[]   = "role {$role->name} rank " . \json_encode($rank) . ' under ' . ($parent->name ?? 'nothing');

            $this->equip($role);
        }
    }

    /**
     * Give the role random permissions and, now and then, a policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \Throwable
     */
    private function equip(Role $role): void
    {
        foreach ($this->random->some(self::HELD, 2) as $name) {
            $this->roleService->grantPermission($role, self::permission($name));
            $this->log[] = "  carries {$name}";
        }

        foreach ($this->random->isOneIn(3) ? [$this->random->pick($this->policies)] : [] as $policy) {
            $this->grantService->attachPolicy($role, $policy);
            $this->log[] = "  attached {$policy->name}";
        }
    }

    /**
     * Create three or four subjects holding roles, permissions and policies in
     * random scopes, and give the actor random administration rights in a
     * random scope, random authority of its own, and a random platform rank.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function subjectsAndActor(): void
    {
        for ($index = 0, $count = $this->random->between(3, 4); $index < $count; $index++) {
            $subject = StubIdentity::query()->create(['id' => 'u' . $index]);

            $this->subjects[] = $subject;
            $this->log[]      = 'subject ' . self::key($subject);

            $this->hold($subject, 2);
        }

        $this->subjects[] = $this->actorModel;

        $rank = $this->random->pick([null, 1, 1, 2, 4]);

        if ($rank !== null) {
            $this->grantService->grantRole($this->actorModel, Role::query()->create(['name' => 'actor-rank', 'rank' => $rank]));
        }

        $rights            = $this->random->isOneIn(5) ? ['authorization:*'] : \array_values(\array_filter(self::RIGHTS, fn (): bool => !$this->random->isOneIn(3)));
        $tenant            = $this->random->isOneIn(4) ? $this->random->pick($this->tenants) : null;
        $this->isGrantable = \in_array('authorization:*', $rights, true);
        $this->log[]       = 'actor rank ' . \json_encode($rank) . ', rights ' . \implode(', ', $rights) . ' in ' . self::key($tenant, 'platform');

        foreach ($rights as $right) {
            $this->grantService->grantPermission($this->actorModel, self::permission($right), tenant: $tenant);
        }

        $this->hold($this->actorModel, 3);
    }

    /**
     * Give the subject random roles, permissions and policies, each in a random
     * scope.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $subject
     * @param  int  $most
     * @return void
     *
     * @throws \Throwable
     */
    private function hold(StubIdentity $subject, int $most): void
    {
        foreach ($this->random->some($this->roles, $most) as $role) {
            $tenant = $this->scope();

            $this->grantService->grantRole($subject, $role, tenant: $tenant);
            $this->log[] = "  holds {$role->name} in " . self::key($tenant, 'platform');
        }

        foreach ($this->random->some(self::HELD, $most) as $name) {
            $tenant = $this->scope();

            $this->grantService->grantPermission($subject, self::permission($name), tenant: $tenant);
            $this->log[] = "  holds {$name} in " . self::key($tenant, 'platform');
        }

        foreach ($this->random->some($this->policies, 1) as $policy) {
            $this->grantService->attachPolicy($subject, $policy);
            $this->log[] = "  attached {$policy->name}";
        }
    }

    /**
     * Set a boundary on some subjects, the actor included, mostly leaving
     * administration alone, so an actor it bounds still administers something.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function boundaries(): void
    {
        foreach ($this->subjects as $subject) {
            if (!$this->random->isOneIn(4)) {
                continue;
            }

            $document = $this->document(false);

            $document['statements'][] = ['effect' => 'allow', 'actions' => $this->random->isOneIn(3) ? ['posts:read'] : ['authorization:*']];

            $this->boundaryService->set($subject, $this->policyService->create('boundary-' . self::key($subject), $document));
            $this->log[] = 'boundary on ' . self::key($subject) . ': ' . \json_encode($document);
        }
    }

    /**
     * Now and then, set a guardrail on the platform or a tenant, and attach to
     * the posts a resource policy naming a role or a subject.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function extras(): void
    {
        $allowed = [...$this->random->some(self::HELD, 4), 'authorization:*'];
        $tenant  = $this->scope();

        foreach ($this->random->isOneIn(3) ? [$this->policyService->create('guardrail', ['statements' => [['effect' => 'allow', 'actions' => $allowed]]])] : [] as $rail) {
            DB::table('guardrails')->insert(['policy_id' => $rail->getKey(), 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()]);
            $this->log[] = 'guardrail in ' . self::key($tenant, 'platform') . ' allowing ' . \implode(', ', $allowed);
        }

        $named    = $this->random->isOneIn(2) ? $this->random->pick($this->roles) : $this->random->pick($this->subjects);
        $selector = ($named instanceof Role ? 'role' : StubIdentity::class) . ':' . self::key($named);
        $actions  = $this->random->some(self::ACTIONS, 2);

        foreach ($this->random->isOneIn(2) ? [['effect' => 'allow', 'actions' => $actions === [] ? ['posts:read'] : $actions, 'principals' => [$selector]]] : [] as $statement) {
            $shared = $this->policyService->create('shared', ['statements' => [$statement]]);

            DB::table('resource_policies')->insert(['policy_id' => $shared->getKey(), 'resource_type' => 'post', 'resource_id' => null]);
            $this->log[] = "resource policy on post naming {$selector}";
        }
    }

    /**
     * Return a random document: one to three statements, allows and, when
     * asked, denies, over the actions, the patterns and, now and then, an
     * administration right.
     *
     * @param  bool  $isDenying
     * @return array{statements: list<array{effect: string, actions: list<string>}>}
     */
    private function document(bool $isDenying = true): array
    {
        $statements = [];

        for ($index = 0, $count = $this->random->between(1, 3); $index < $count; $index++) {
            $pool    = [...self::ACTIONS, ...self::PATTERNS, ...($this->random->isOneIn(5) ? self::RIGHTS : [])];
            $actions = $this->random->some($pool, 2);

            $statements[] = ['effect' => $isDenying && $this->random->isOneIn(4) ? 'deny' : 'allow', 'actions' => $actions === [] ? [$this->random->pick($pool)] : $actions];
        }

        return ['statements' => $statements];
    }

    /**
     * Return a role the role may be put under without a cycle, or null.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Models\Role|null
     */
    private function parentFor(Role $role): ?Role
    {
        $earlier = \array_slice($this->roles, 0, (int) \array_search($role, $this->roles, true));

        return $earlier === [] || $this->random->isOneIn(4) ? null : $this->random->pick($earlier);
    }

    /**
     * Return a random scope: the platform or a tenant.
     *
     * @return \Tests\Feature\Stubs\StubTenant|null
     */
    private function scope(): ?StubTenant
    {
        return $this->random->isOneIn(2) ? null : $this->random->pick($this->tenants);
    }

    /**
     * Return the permission of the name, created when there is none.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }
}
