<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Authorization\Support\TenantColumns;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for rows naming half a tenant, a key without a type or a type
 * without a key, which the package never writes (N130): such a row is neither
 * the platform's nor any tenant's, and fails closed both ways. One that grants
 * (a role, permission or policy grant, a role's policy attachment, the
 * ownership of a role or a permission) applies nowhere; one that restricts (a
 * boundary, a guardrail, a deny attached to a grantee, to a role or to a
 * resource) applies everywhere: at the platform, in an organisation, in an
 * account below it in a closure-table tree and in another organisation, through
 * a check, a bulk check, `permissionsFor()` and `whereAuthorized()` alike, and
 * again once the resolution cache holds the answers. An attachment that both
 * allows and denies, stored that way or of a policy naming half a tenant,
 * denies everywhere and allows nowhere. A row naming a whole tenant, and a
 * platform row, hold as they always have.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TenantChain::class)]
#[CoversClass(TenantColumns::class)]
final class HalfTenantRowsTest extends TestCase
{
    use CatchesRefusals, ScopesQueries {
        CatchesRefusals::refusalOf insteadof ScopesQueries;
    }

    /** @var string The action every row grants or refuses. */
    private const string ACTION = 'posts:create';

    /** @var string The action an attachment that both allows and denies refuses. */
    private const string DENIED = 'posts:delete';

    /** @var list<string> The kinds of row that cap or deny the action rather than grant it. */
    private const array LIMITS = ['resource policy', 'boundary', 'guardrail', 'deny attachment', 'deny role policy attachment'];

    /** @var list<string> The kinds of attachment that both allow one action and deny another. */
    private const array MIXED = ['policy attachment', 'role policy attachment', 'resource policy'];

    /** @var list<string> The kinds of row that own what is granted. */
    private const array OWNERSHIPS = ['role ownership', 'permission ownership'];

    /** @var list<string> The scopes a check is decided in: the platform, the organisation, the account below it and another organisation. */
    private const array SCOPES = ['platform', 'o1', 'a1', 'o2'];

    /**
     * Return each kind of row with each pair of tenant columns, and the scopes
     * the action is allowed in: a grant admits it where it applies, a cap or a
     * deny refuses it there, and a row owning a role or a permission granted in
     * the organisation admits it there; a row naming half a tenant admits it
     * nowhere, granting nowhere and restricting everywhere.
     *
     * @return iterable<string, array{string, string|null, string|null, list<string>}>
     */
    public static function rows(): iterable
    {
        $everywhere = self::SCOPES;
        $placed     = ['o1', 'a1'];
        $outside    = ['platform', 'o2'];

        $expected = [
            'role grant'                  => [[], $placed, $everywhere],
            'permission grant'            => [[], $placed, $everywhere],
            'policy attachment'           => [[], $placed, $everywhere],
            'role policy attachment'      => [[], $placed, $everywhere],
            'resource policy'             => [[], $outside, []],
            'boundary'                    => [[], $outside, []],
            'guardrail'                   => [[], $outside, []],
            'deny attachment'             => [[], $outside, []],
            'deny role policy attachment' => [[], $outside, []],
            'role ownership'              => [[], $placed, $placed],
            'permission ownership'        => [[], $placed, $placed],
        ];

        foreach ($expected as $kind => [$half, $whole, $platform]) {
            yield "{$kind}, a key without a type" => [$kind, null, 'o1', $half];
            yield "{$kind}, a type without a key" => [$kind, 'tenant', null, $half];
            yield "{$kind}, a whole tenant" => [$kind, 'tenant', 'o1', $whole];
            yield "{$kind}, the platform" => [$kind, null, null, $platform];
        }
    }

    /**
     * Every kind of row, stored with each pair of tenant columns, admits the
     * action exactly where it applies: a row naming the organisation there and
     * below it, and a platform row everywhere, for a grant, and the reverse for
     * what caps or denies; a row naming half a tenant admits it nowhere, a
     * grant applying nowhere and a cap or a deny everywhere.
     *
     * @param  string  $kind
     * @param  string|null  $type
     * @param  string|null  $id
     * @param  list<string>  $allowed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('rows')]
    public function testARowAppliesExactlyWhereItsTenantColumnsPlaceIt(string $kind, ?string $type, ?string $id, array $allowed): void
    {
        $tenants = $this->tree();
        $posts   = self::posts($tenants);
        $user    = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new NoResourceTenant));

        self::store($kind, $user, $type === 'tenant' ? (new StubTenant)->getMorphClass() : $type, $id);

        $isResourceOnly = $kind === 'resource policy';

        foreach ([1, 2] as $round) {
            foreach (self::SCOPES as $scope) {
                $manager  = $this->resolveRequest($user, $tenants[$scope]);
                $post     = $posts[$scope];
                $expected = \in_array($scope, $allowed, true);
                $message  = "{$kind} [{$type}, {$id}] in {$scope}, round {$round}";
                $bulk     = $manager->checkMany(['post' => new CheckInput(self::ACTION, $post), 'none' => new CheckInput(self::ACTION)]);
                $kept     = TenantScopedPost::query()->whereAuthorized(self::ACTION, [], $manager)->pluck('id')->all(); // @phpstan-ignore method.notFound
                $listed   = $manager->permissionsFor(null, AuthorizationScope::current());

                self::assertSame($expected, $manager->can(self::ACTION, $post), $message);
                self::assertSame($expected, $bulk['post']->isAllowed(), $message);
                self::assertSame($expected || $isResourceOnly, $bulk['none']->isAllowed(), $message);
                self::assertSame($expected || $isResourceOnly, $manager->can(self::ACTION), $message);
                self::assertSame($expected || $isResourceOnly, \in_array(self::ACTION, $listed, true), $message);
                self::assertSame($expected, \in_array($post->getKey(), $kept, true), $message);
            }
        }
    }

    /**
     * Return each kind of attachment that both allows the action and denies
     * another, stored naming half a tenant, or naming the organisation for a
     * policy naming half a tenant, or, as a control, naming the organisation
     * for a policy the platform owns, with the scopes the action is allowed in
     * and those the other action is.
     *
     * @return iterable<string, array{string, array<string, string|null>, array<string, string|null>, list<string>, list<string>}>
     */
    public static function mixed(): iterable
    {
        $whole = ['tenant_type' => 'tenant', 'tenant_id' => 'o1'];

        foreach (self::MIXED as $kind) {
            yield "{$kind}, a key without a type" => [$kind, ['tenant_type' => null, 'tenant_id' => 'o1'], [], [], []];
            yield "{$kind}, a type without a key" => [$kind, ['tenant_type' => 'tenant', 'tenant_id' => null], [], [], []];
            yield "{$kind}, of a policy with a key without a type" => [$kind, $whole, ['tenant_type' => null], [], []];
            yield "{$kind}, of a policy with a type without a key" => [$kind, $whole, ['tenant_id' => null], [], []];
            yield "{$kind}, a whole tenant" => [$kind, $whole, [], ['o1', 'a1'], ['platform', 'o2']];
        }
    }

    /**
     * An attachment that allows the action and denies another, stored naming
     * half a tenant, or of a policy naming half a tenant, denies the other
     * action everywhere and allows the action nowhere: through a check, a bulk
     * check, `permissionsFor()` and `whereAuthorized()`, cold and warm. One
     * naming the organisation, of a policy the platform owns, allows and denies
     * there and below it alone.
     *
     * @param  string  $kind
     * @param  array<string, string|null>  $columns
     * @param  array<string, string|null>  $owner
     * @param  list<string>  $allowed
     * @param  list<string>  $permitted
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('mixed')]
    public function testAnAttachmentNamingHalfATenantDeniesEverywhereAndAllowsNowhere(string $kind, array $columns, array $owner, array $allowed, array $permitted): void
    {
        $tenants = $this->tree();
        $posts   = self::posts($tenants);
        $user    = StubIdentity::create(['id' => 'user-1']);
        $tenant  = (new StubTenant)->getMorphClass();

        $this->app?->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new NoResourceTenant));

        $columns = \array_map(static fn (?string $value): ?string => $value === 'tenant' ? $tenant : $value, $columns);

        self::storeMixed($kind, $user, $posts, $columns, \array_map(static fn (?string $value): ?string => $value === 'tenant' ? $tenant : $value, $owner));

        $isResource = $kind === 'resource policy';

        foreach ([1, 2] as $round) {
            foreach (self::SCOPES as $scope) {
                $manager = $this->resolveRequest($user, $tenants[$scope]);
                $message = "{$kind} in {$scope}, round {$round}";

                $expected = [self::ACTION => \in_array($scope, $allowed, true), self::DENIED => \in_array($scope, $permitted, true)];

                self::assertDecided($manager, $posts[$scope], $message, $expected, $isResource);
            }
        }
    }

    /**
     * A policy naming half a tenant is attached nowhere, to a grantee, as a
     * boundary or to a resource, at the platform or in a tenant, rather than
     * taken as the platform's; one the platform owns is attached.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyNamingHalfATenantIsAttachedNowhere(): void
    {
        $tenants = $this->tree();
        $user    = StubIdentity::create(['id' => 'user-1']);
        $grants  = $this->app?->make(GrantService::class);

        self::assertInstanceOf(GrantService::class, $grants);

        foreach (['no-type' => ['tenant_type' => null], 'no-key' => ['tenant_id' => null]] as $name => $columns) {
            $policy = Policy::create(['name' => $name, 'tenant_type' => (new StubTenant)->getMorphClass(), 'tenant_id' => 'o1', 'document' => ['statements' => []]]);

            DB::table('policies')->where('id', $policy->getKey())->update($columns);

            $stored = Policy::query()->whereKey($policy->getKey())->firstOrFail();

            foreach ([null, $tenants['o1']] as $tenant) {
                $attachments = [
                    static fn () => $grants->attachPolicy($user, $stored, tenant: $tenant),
                    static fn () => BoundaryService::instance()?->set($user, $stored, $tenant),
                    static fn () => ResourcePolicyService::instance()?->attach($stored, TenantScopedPost::class, $tenant),
                ];

                foreach ($attachments as $attach) {
                    self::assertInstanceOf(InvalidTenantColumnsException::class, self::refusalOf($attach), $name);
                }
            }
        }

        foreach (['authorizable_policies', 'authorizable_boundaries', 'resource_policies'] as $table) {
            self::assertSame(0, DB::table($table)->count(), $table);
        }

        $grants->attachPolicy($user, Policy::create(['name' => 'platform', 'document' => ['statements' => []]]));

        self::assertSame(1, DB::table('authorizable_policies')->count());
    }

    /**
     * A deny of a policy an attachment naming half a tenant attaches is named
     * at its position in the policy's document whether the check reads the
     * policy afresh or from the persistent resolution cache.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADenyIsNamedAtItsPositionColdOrWarm(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'p', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => [self::ACTION]],
            ['effect' => 'deny', 'actions' => [self::DENIED], 'sid' => 'NoDelete'],
        ]]]);

        DB::table('authorizable_policies')->insert([
            'policy_id'         => $policy->getKey(),
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => Reference::of($user)->id,
            'tenant_type'       => (new StubTenant)->getMorphClass(),
            'tenant_id'         => null,
        ]);

        $cold = $this->resolveRequest($user)->explain(self::DENIED)->toText();

        self::assertFalse($this->resolveRequest($user)->can(self::DENIED));

        $warm = $this->resolveRequest($user)->explain(self::DENIED)->toText();

        self::assertStringContainsString('#1 sid="NoDelete"', $cold);
        self::assertSame($cold, $warm);
    }

    /**
     * Use a persistent resolution cache, so the second round of checks reads
     * what the first stored.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * Assert each action is allowed on the post as expected through a check, a
     * bulk check and query scoping, and on no resource through a check and the
     * permissions listed, where an attachment to a resource neither allows nor
     * denies but the action's permission alone decides.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  \Tests\Fixtures\QueryScoping\TenantScopedPost  $post
     * @param  string  $message
     * @param  array<string, bool>  $expected
     * @param  bool  $isResource
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertDecided(AuthorizationManager $manager, TenantScopedPost $post, string $message, array $expected, bool $isResource): void
    {
        $inputs = [];

        foreach (\array_keys($expected) as $action) {
            $inputs[$action] = new CheckInput($action, $post);
        }

        $bulk   = $manager->checkMany($inputs);
        $listed = $manager->permissionsFor(null, AuthorizationScope::current());

        foreach ($expected as $action => $isAllowed) {
            $bare = $isResource ? $action === self::DENIED : $isAllowed;
            $kept = TenantScopedPost::query()->whereAuthorized($action, [], $manager)->pluck('id')->all(); // @phpstan-ignore method.notFound

            self::assertSame($isAllowed, $manager->can($action, $post), "{$message}: {$action}");
            self::assertSame($isAllowed, $bulk[$action]->isAllowed(), "{$message}: {$action}");
            self::assertSame($isAllowed, \in_array($post->getKey(), $kept, true), "{$message}: {$action}");
            self::assertSame($bare, $manager->can($action), "{$message}: {$action}, no resource");
            self::assertSame($bare, \in_array($action, $listed, true), "{$message}: {$action}, listed");
        }
    }

    /**
     * Bind a closure-table tree of an organisation with an account below it,
     * and another organisation, and return each tenant by its scope's name,
     * none for the platform.
     *
     * @return array<string, \Tests\Feature\Stubs\StubTenant|null>
     */
    private function tree(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        $tenants = ['platform' => null];

        foreach (['o1', 'a1', 'o2'] as $id) {
            $tenants[$id] = StubTenant::query()->create(['id' => $id, 'name' => $id]);
        }

        ClosureTenantTree::add(Reference::of($tenants['o1']));
        ClosureTenantTree::add(Reference::of($tenants['a1']), Reference::of($tenants['o1']));
        ClosureTenantTree::add(Reference::of($tenants['o2']));

        return $tenants;
    }

    /**
     * Create a post in each scope, the platform's naming no tenant, and return
     * each by its scope's name.
     *
     * @param  array<string, \Tests\Feature\Stubs\StubTenant|null>  $tenants
     * @return array<string, \Tests\Fixtures\QueryScoping\TenantScopedPost>
     */
    private static function posts(array $tenants): array
    {
        $posts = [];

        foreach ($tenants as $scope => $tenant) {
            $posts[$scope] = TenantScopedPost::query()->create(['title' => $scope, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()]);
        }

        return $posts;
    }

    /**
     * Store the row of the kind with the tenant columns given, reaching the
     * tenants below, with what it needs to grant or refuse the action: a
     * platform-wide grant of the action beside a cap or a deny, and a role or
     * permission owned as the columns say, granted in the organisation.
     *
     * @param  string  $kind
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string|null  $type
     * @param  string|null  $id
     * @return void
     */
    private static function store(string $kind, StubIdentity $user, ?string $type, ?string $id): void
    {
        $columns = ['tenant_type' => $type, 'tenant_id' => $id];
        $grantee = ['authorizable_type' => $user->getMorphClass(), 'authorizable_id' => Reference::of($user)->id, 'include_subtree' => true];

        if (\in_array($kind, self::OWNERSHIPS, true)) {
            self::own($kind, $grantee, $columns);

            return;
        }

        [$table, $row] = \in_array($kind, self::LIMITS, true) ? self::limiting($kind, $grantee) : self::granting($kind, $grantee);

        DB::table($table)->insert([...$row, ...$columns]);
    }

    /**
     * Return the table and the row, its tenant columns aside, of a grant of the
     * kind: a role carrying the action, the action's permission, or a policy
     * allowing it, attached to the grantee or to a role the grantee holds
     * platform-wide.
     *
     * @param  string  $kind
     * @param  array<string, bool|string>  $grantee
     * @return array{string, array<string, mixed>}
     */
    private static function granting(string $kind, array $grantee): array
    {
        return match ($kind) {
            'role grant'        => ['authorizable_roles', ['role_id' => self::role()->getKey(), ...$grantee]],
            'permission grant'  => ['authorizable_permissions', ['permission_id' => self::permission()->getKey(), ...$grantee]],
            'policy attachment' => ['authorizable_policies', ['policy_id' => self::policy('allow', self::ACTION)->getKey(), ...$grantee]],
            default             => ['authorizable_policies', self::roleAttachment($grantee)],
        };
    }

    /**
     * Grant a role to the grantee platform-wide, and return the row, its tenant
     * columns aside, attaching a policy allowing, or denying, the action to it.
     *
     * @param  array<string, bool|string>  $grantee
     * @param  string  $effect
     * @return array<string, mixed>
     */
    private static function roleAttachment(array $grantee, string $effect = 'allow'): array
    {
        $role = Role::create(['name' => 'carrier']);

        DB::table('authorizable_roles')->insert(['role_id' => $role->getKey(), ...$grantee]);

        return [
            'policy_id'         => self::policy($effect, self::ACTION)->getKey(),
            'authorizable_type' => $role->getMorphClass(),
            'authorizable_id'   => Reference::of($role)->id,
            'include_subtree'   => true,
        ];
    }

    /**
     * Grant the action to the grantee platform-wide, and return the table and
     * the row, its tenant columns aside, of what of the kind caps or denies it:
     * a deny attached to the posts, to the grantee or to a role it holds
     * platform-wide, or a boundary or a guardrail allowing another action
     * alone.
     *
     * @param  string  $kind
     * @param  array<string, bool|string>  $grantee
     * @return array{string, array<string, mixed>}
     */
    private static function limiting(string $kind, array $grantee): array
    {
        DB::table('authorizable_permissions')->insert(['permission_id' => self::permission()->getKey(), ...$grantee]);

        return match ($kind) {
            'resource policy'             => ['resource_policies', ['policy_id' => self::policy('deny', self::ACTION)->getKey(), 'resource_type' => self::postType()]],
            'boundary'                    => ['authorizable_boundaries', ['policy_id' => self::policy('allow', 'other:*')->getKey(), ...$grantee]],
            'deny attachment'             => ['authorizable_policies', ['policy_id' => self::policy('deny', self::ACTION)->getKey(), ...$grantee]],
            'deny role policy attachment' => ['authorizable_policies', self::roleAttachment($grantee, 'deny')],
            default                       => ['guardrails', ['policy_id' => self::policy('allow', 'other:*')->getKey()]],
        };
    }

    /**
     * Grant the other action to the grantee platform-wide, then attach a policy
     * allowing the action and denying the other, owned as the owner columns
     * say, with the tenant columns given, reaching below: to the grantee, to a
     * role it holds platform-wide, or to each post.
     *
     * @param  string  $kind
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  array<string, \Tests\Fixtures\QueryScoping\TenantScopedPost>  $posts
     * @param  array<string, string|null>  $columns
     * @param  array<string, string|null>  $owner
     * @return void
     */
    private static function storeMixed(string $kind, StubIdentity $user, array $posts, array $columns, array $owner): void
    {
        $grantee = ['authorizable_type' => $user->getMorphClass(), 'authorizable_id' => Reference::of($user)->id, 'include_subtree' => true];
        $allow   = ['effect' => 'allow', 'actions' => [self::ACTION]];
        $deny    = ['effect' => 'deny', 'actions' => [self::DENIED]];
        $other   = Permission::query()->withoutGlobalScopes()->firstOrCreate(['name' => self::DENIED]);

        DB::table('authorizable_permissions')->insert(['permission_id' => $other->getKey(), ...$grantee]);

        $principal = $kind === 'resource policy' ? ['principals' => [$user->getMorphClass() . ':user-1']] : [];
        $policy    = Policy::create(['name' => 'mixed', 'document' => ['statements' => [[...$allow, ...$principal], $deny]]]);
        $rows      = match ($kind) {
            'policy attachment'      => [['policy_id' => $policy->getKey(), ...$grantee]],
            'role policy attachment' => [['policy_id' => $policy->getKey(), ...\array_diff_key(self::roleAttachment($grantee), ['policy_id' => true])]],
            default                  => \array_values(\array_map(static fn (TenantScopedPost $post): array => [
                'policy_id'       => $policy->getKey(),
                'resource_type'   => $post->getMorphClass(),
                'resource_id'     => (string) $post->getKey(), // @phpstan-ignore cast.string
                'include_subtree' => true,
            ], $posts)),
        };

        foreach ($rows as $row) {
            DB::table($kind === 'resource policy' ? 'resource_policies' : 'authorizable_policies')->insert([...$row, ...$columns]);
        }

        // A policy the platform owns is left as it is.
        $owned = $owner === [] ? ['tenant_type' => null, 'tenant_id' => null] : [...['tenant_type' => 'tenant-type', 'tenant_id' => 'o1'], ...$owner];

        DB::table('policies')->where('id', $policy->getKey())->update($owned);
    }

    /**
     * Return the morph type of the posts.
     *
     * @return string
     */
    private static function postType(): string
    {
        return (new TenantScopedPost)->getMorphClass();
    }

    /**
     * Grant a role or permission the organisation owns to the grantee there,
     * reaching below it, then store its owner as the tenant columns given.
     *
     * @param  string  $kind
     * @param  array<string, bool|string>  $grantee
     * @param  array<string, string|null>  $columns
     * @return void
     */
    private static function own(string $kind, array $grantee, array $columns): void
    {
        $whole = ['tenant_type' => (new StubTenant)->getMorphClass(), 'tenant_id' => 'o1'];

        [$table, $grants, $column, $key] = $kind === 'role ownership'
            ? ['roles', 'authorizable_roles', 'role_id', self::role($whole)->getKey()]
            : ['permissions', 'authorizable_permissions', 'permission_id', self::permission($whole)->getKey()];

        DB::table($grants)->insert([$column => $key, ...$grantee, ...$whole]);
        DB::table($table)->where('id', $key)->update($columns);
    }

    /**
     * Create a role carrying the action, owned as the columns say.
     *
     * @param  array<string, string>  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(array $owner = []): Role
    {
        $role = Role::create(['name' => 'viewer', ...$owner]);

        $role->givePermission(self::permission());

        return $role;
    }

    /**
     * Return the permission of the action, owned as the columns say, creating
     * it the first time.
     *
     * @param  array<string, string>  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(array $owner = []): Permission
    {
        return Permission::query()->withoutGlobalScopes()->firstOrCreate(['name' => self::ACTION, ...$owner]);
    }

    /**
     * Create a policy of one statement of the effect on the action.
     *
     * @param  string  $effect
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $effect, string $action): Policy
    {
        return Policy::create(['name' => $effect . ' ' . $action, 'document' => ['statements' => [['effect' => $effect, 'actions' => [$action]]]]]);
    }
}
