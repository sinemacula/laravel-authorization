<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\PossessionLimits;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\BulkChecks\FailingTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `PossessionLimits`, whether anything that caps or denies a
 * subject could limit a permission anywhere a delegated grant of it would
 * reach.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PossessionLimits::class)]
final class PossessionLimitsTest extends TestCase
{
    /**
     * Pairs of action patterns, and whether they name an action in common.
     *
     * @return iterable<string, array{string, string, bool}>
     */
    public static function patterns(): iterable
    {
        yield 'the same name' => ['posts:edit', 'posts:edit', true];
        yield 'another name' => ['posts:edit', 'posts:read', false];
        yield 'a pattern covering a name' => ['posts:*', 'posts:edit', true];
        yield 'a name a pattern covers' => ['posts:edit', 'posts:*', true];
        yield 'a pattern not covering a name' => ['billing:*', 'posts:edit', false];
        yield 'two patterns sharing a prefix' => ['posts:*', 'posts:e*', true];
        yield 'two patterns of other prefixes' => ['posts:*', 'billing:*', false];
        yield 'two patterns sharing a suffix' => ['*:edit', 'posts:*', true];
        yield 'two patterns of other suffixes' => ['*:edit', '*:read', false];
        yield 'two patterns, one inside the other' => ['*', 'a*b', true];
        yield 'a suffix the other ends' => ['*b', 'a*ab', true];
        yield 'a prefix and a suffix that clash' => ['a*', 'b*', false];
        yield 'suffixes differing before their last character' => ['*ab', '*bb', false];
        yield 'a class matching a name' => ['[p]osts:edit', 'posts:edit', true];
        yield 'a class matching another name' => ['[p]osts:edit', 'posts:read', false];
        yield 'a class against a pattern' => ['[p]osts:edit', 'posts:*', true];
        yield 'a single wildcard against a pattern' => ['p?sts:edit', 'posts:*', true];
        yield 'a single wildcard against an unrelated pattern' => ['p?sts:*', 'billing:*', true];
    }

    /**
     * Two patterns overlap exactly when some action matches both, and two that
     * both hold wildcards, one of them `?` or a class, are taken to overlap.
     *
     * @param  string  $pattern
     * @param  string  $other
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('patterns')]
    public function testPatternsOverlapWhenAnActionMatchesBoth(string $pattern, string $other, bool $expected): void
    {
        self::assertSame($expected, PossessionLimits::isOverlapping($pattern, $other));
        self::assertSame($expected, PossessionLimits::isOverlapping($other, $pattern));
    }

    /**
     * Nothing limits a permission when nothing denies or caps the subject.
     *
     * @return void
     */
    public function testNothingLimitsWhenNothingDeniesOrCaps(): void
    {
        self::assertFalse(self::limits('posts:edit'));
    }

    /**
     * A deny statement among the check's policies limits the permission when it
     * names an action the permission covers, with conditions, resource patterns
     * or none, or when its `not_actions` leave any of them; one naming none of
     * them does not.
     *
     * @return void
     */
    public function testADenyNamingThePermissionLimitsIt(): void
    {
        $deny = static fn (array $statement): array => ['policies' => [self::policy([['effect' => 'deny', ...$statement]])]];

        self::assertTrue(self::limits('posts:edit', $deny(['actions' => ['posts:edit']])));
        self::assertTrue(self::limits('posts:*', $deny(['actions' => ['posts:edit']])));
        self::assertTrue(self::limits('posts:edit', $deny(['actions' => ['posts:edit'], 'resources' => ['posts:secret:*']])));
        self::assertTrue(self::limits('posts:edit', $deny(['actions' => ['posts:edit'], 'conditions' => ['null' => ['request.ip' => false]]])));
        self::assertTrue(self::limits('posts:edit', $deny(['not_actions' => ['posts:read']])));
        self::assertFalse(self::limits('posts:edit', $deny(['not_actions' => ['posts:*']])));
        self::assertFalse(self::limits('posts:edit', $deny(['actions' => ['posts:read']])));
        self::assertFalse(self::limits('posts:edit', ['policies' => [self::policy([['effect' => 'allow', 'actions' => ['billing:*']]])]]));
        self::assertTrue(self::limits('posts:*', $deny(['actions' => ['[p]osts:edit']])));
        self::assertTrue(self::limits('posts:*', $deny(['actions' => ['p?sts:edit']])));
        self::assertFalse(self::limits('posts:read', $deny(['actions' => ['[p]osts:edit']])));
    }

    /**
     * Every boundary and guardrail must allow every action the permission
     * covers, with no condition, on every resource: a cap allowing it on some
     * resources only, under a condition, or not at all, limits it; a pattern
     * holding `?` or a class covers no wildcard, and excludes one it could
     * overlap.
     *
     * @return void
     */
    public function testEveryCapMustAllowThePermissionWhole(): void
    {
        $cap = static fn (array $statement, string $kind = 'boundaries'): array => [$kind => [self::policy([['effect' => 'allow', ...$statement]])]];

        self::assertFalse(self::limits('posts:edit', $cap(['actions' => ['posts:*']])));
        self::assertFalse(self::limits('posts:edit', $cap(['actions' => ['posts:edit'], 'resources' => ['*']])));
        self::assertFalse(self::limits('posts:edit', $cap(['not_actions' => ['billing:*']])));
        self::assertFalse(self::limits('posts:edit', $cap(['actions' => ['*']], 'guardrails')));
        self::assertTrue(self::limits('posts:edit', $cap(['actions' => ['posts:read']])));
        self::assertTrue(self::limits('posts:*', $cap(['actions' => ['posts:edit']])));
        self::assertTrue(self::limits('posts:edit', $cap(['actions' => ['posts:edit'], 'resources' => ['posts:mine:*']])));
        self::assertTrue(self::limits('posts:edit', $cap(['actions' => ['posts:edit'], 'not_resources' => ['posts:secret:*']])));
        self::assertTrue(self::limits('posts:edit', $cap(['actions' => ['posts:edit'], 'conditions' => ['null' => ['request.ip' => true]]])));
        self::assertTrue(self::limits('posts:edit', $cap(['not_actions' => ['posts:e*']])));
        self::assertTrue(self::limits('posts:edit', $cap(['actions' => ['posts:read']], 'guardrails')));
        self::assertTrue(self::limits('posts:edit', ['boundaries' => [self::policy([['effect' => 'deny', 'actions' => ['billing:*']]])]]));
        self::assertTrue(self::limits('posts:*', $cap(['not_actions' => ['[p]osts:edit']])));
        self::assertTrue(self::limits('posts:*', $cap(['actions' => ['p?sts:*']])));
        self::assertTrue(self::limits('posts:*', $cap(['actions' => ['posts:[!x]*']])));
        self::assertFalse(self::limits('posts:edit', $cap(['actions' => ['p?sts:*']])));
    }

    /**
     * Every session cap must cover every action the permission covers; an empty
     * one covers nothing.
     *
     * @return void
     */
    public function testEverySessionCapMustCoverThePermission(): void
    {
        self::assertFalse(self::limits('posts:edit', ['session' => [['credential', ['posts:*']], ['capped[1]', ['posts:edit']]]]));
        self::assertTrue(self::limits('posts:edit', ['session' => [['credential', ['posts:*']], ['capped[1]', ['posts:read']]]]));
        self::assertTrue(self::limits('posts:*', ['session' => [['credential', ['posts:edit']]]]));
        self::assertTrue(self::limits('posts:edit', ['session' => [['credential:missing', []]]]));
        self::assertTrue(self::limits('posts:*', ['session' => [['credential', ['posts:?*']]]]));
        self::assertFalse(self::limits('posts:edit', ['session' => [['credential', ['posts:?dit']]]]));
    }

    /**
     * The policies stored for the subject limit the permission whatever their
     * scope: those attached to its principal, to its identity, and to a role
     * either holds or a role above it, and those attached to any resource.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStoredPoliciesOfTheSubjectAndItsRolesLimit(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $identity  = StubIdentity::create(['id' => 'person-1']);
        $staff     = Role::create(['name' => 'staff']);
        $editor    = Role::create(['name' => 'editor', 'parent_id' => $staff->id]);
        $subject   = new Subject($principal, $identity);

        self::grants()->grantRole($identity, $editor, tenant: new Reference('tenant', 'elsewhere'));

        self::assertFalse(self::limits('posts:edit', subject: $subject));

        self::grants()->attachPolicy($staff, self::denying('staff-deny', 'posts:edit'));

        self::assertTrue(self::limits('posts:edit', subject: $subject));
        self::assertFalse(self::limits('posts:read', subject: $subject));

        self::grants()->attachPolicy($identity, self::denying('identity-deny', 'posts:read'), application: 'mobile');

        self::assertTrue(self::limits('posts:read', subject: $subject));

        self::grants()->attachPolicy($principal, self::denying('principal-deny', 'posts:draft'));

        self::assertTrue(self::limits('posts:draft', subject: $subject));

        ResourcePolicyService::instance()?->attach(self::denying('resource-deny', 'posts:share'), ['posts', 7]);

        self::assertTrue(self::limits('posts:share', subject: $subject));
        self::assertFalse(self::limits('posts:publish', subject: $subject));
    }

    /**
     * The subject's stored boundaries and the guardrails limit the permission
     * when they are held in the grant's reach: the platform, the grant's tenant
     * and its ancestors, and, for a grant reaching below, every tenant below
     * it; a platform-wide grant reaches every tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStoredCapsInTheReachLimit(): void
    {
        [$parent, $child, $other] = [new Reference('tenant', 'parent'), new Reference('tenant', 'child'), new Reference('tenant', 'other')];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($child, $parent));

        $user    = StubIdentity::create(['id' => 'user-1']);
        $manager = StubIdentity::create(['id' => 'manager']);
        $narrow  = self::allowing('narrow', 'posts:read');

        self::grants()->grantPermission($manager, Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        GuardrailService::instance()?->set($narrow, $child, ActingContext::for($manager));

        self::assertFalse(self::limits('posts:edit', subject: new Subject($user, $user), scope: new GrantScope($parent, null, false)));
        self::assertFalse(self::limits('posts:edit', subject: new Subject($user, $user), scope: new GrantScope($other)));
        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user), scope: new GrantScope($parent)));
        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user), scope: new GrantScope($child, null, false)));
        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user)));
        self::assertFalse(self::limits('posts:read', subject: new Subject($user, $user)));

        BoundaryService::instance()?->set($user, self::allowing('bound', 'posts:edit'), $other);

        self::assertTrue(self::limits('posts:read', subject: new Subject($user, $user)));
        self::assertTrue(self::limits('posts:read', subject: new Subject($user, $user), scope: new GrantScope($other)));
        self::assertFalse(self::limits('posts:read', subject: new Subject($user, $user), scope: new GrantScope($child)));
    }

    /**
     * More resource-policy attachments, or more guardrails, in the reach than
     * the impact limit allows limit every permission; inside a delegated
     * operation, those within it are locked and pinned, with the policies read,
     * so a deny attached before the write is noticed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttachmentsAndGuardrailsOfTheReachAreBoundedAndPinned(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $allow   = self::allowing('open', 'posts:read');

        foreach (['1', '2'] as $id) {
            DB::table('resource_policies')->insert(['policy_id' => $allow->getKey(), 'resource_type' => 'posts', 'resource_id' => $id]);
        }

        config(['authorization.administration.max_impact' => 1]);

        self::assertTrue(self::limits('posts:edit', subject: $subject));

        config(['authorization.administration.max_impact' => 2]);

        self::assertFalse(self::limits('posts:edit', subject: $subject));

        DB::table('resource_policies')->delete();
        DB::table('guardrails')->insert(['policy_id' => self::allowing('rail', '*')->getKey(), 'tenant_type' => null, 'tenant_id' => null]);
        DB::table('guardrails')->insert(['policy_id' => self::allowing('other', '*')->getKey(), 'tenant_type' => 'tenant', 'tenant_id' => 'a']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(new Reference('tenant', 'a'), null)->put(new Reference('tenant', 'b'), null));

        config(['authorization.administration.max_impact' => 1]);

        self::assertFalse(self::limits('posts:edit', subject: $subject, scope: new GrantScope(new Reference('tenant', 'b'))));
        self::assertTrue(self::limits('posts:edit', subject: $subject, scope: new GrantScope(new Reference('tenant', 'a'))));
        self::assertTrue(self::limits('posts:edit', subject: $subject));

        config(['authorization.administration.max_impact' => 2]);

        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);
        $deny      = self::denying('deny', 'posts:edit');

        $noticed = OperationScope::run($operation, static function () use ($subject, $deny): bool {
            self::assertFalse(self::limits('posts:edit', subject: $subject));

            OperationScope::delegatedPins()->validate();

            DB::table('resource_policies')->insert(['policy_id' => $deny->getKey(), 'resource_type' => 'posts', 'resource_id' => '3']);

            try {
                OperationScope::delegatedPins()->validate();
            } catch (DependencyChangedException) {
                return true;
            }

            return false;
        });

        self::assertTrue($noticed);
    }

    /**
     * A stored policy whose document cannot be read limits every permission.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadableStoredPolicyLimits(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::allowing('broken', 'posts:read');

        self::grants()->attachPolicy($user, $policy);

        DB::table('policies')->where('id', $policy->id)->update(['document' => '{"statements": "not a list"}']);

        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user)));
    }

    /**
     * Only the subject's own stored rows count: a deny, a role and a boundary
     * of another identity never limit it, and a subject with no stored grantee
     * reads none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGranteesRowsNeverLimit(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $other = StubIdentity::create(['id' => 'other']);
        $role  = Role::create(['name' => 'theirs']);

        self::grants()->grantRole($other, $role);
        self::grants()->attachPolicy($other, self::denying('other-deny', 'posts:edit'));
        self::grants()->attachPolicy($role, self::denying('role-deny', 'posts:edit'));
        BoundaryService::instance()?->set($other, self::allowing('other-bound', 'posts:read'));

        self::assertFalse(self::limits('posts:edit', subject: new Subject($user, $user)));
        self::assertFalse(self::limits('posts:edit'));

        self::grants()->attachPolicy($user, self::denying('own-deny', 'posts:edit'));

        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user)));
    }

    /**
     * A role held only outside the grant's reach never limits it, though it
     * limits a platform-wide grant, which reaches every tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleHeldOutsideTheReachNeverLimits(): void
    {
        $user = StubIdentity::create(['id' => 'user-9']);
        $role = Role::create(['name' => 'away']);

        self::grants()->grantRole($user, $role, tenant: new Reference('tenant', 'other'));
        self::grants()->attachPolicy($role, self::denying('away-deny', 'posts:edit'));

        self::assertFalse(self::limits('posts:edit', subject: new Subject($user, $user), scope: new GrantScope(new Reference('tenant', 'a'), null, false)));
        self::assertTrue(self::limits('posts:edit', subject: new Subject($user, $user)));
    }

    /**
     * A tree that cannot be read for the grant's tenant limits every
     * permission, so the reach is never guessed.
     *
     * @return void
     */
    public function testATreeThatCannotBeReadLimits(): void
    {
        $this->app?->instance(TenantTree::class, new FailingTenantTree(failing: ['a']));

        self::assertTrue(self::limits('posts:edit', scope: new GrantScope(new Reference('tenant', 'a'))));
        self::assertFalse(self::limits('posts:edit', scope: new GrantScope(new Reference('tenant', 'b'), null, false)));
    }

    /**
     * Many permissions are weighed in one pass, each keyed by its name, each by
     * its own sources and by what is stored in the reach, read once for them
     * all; none to weigh reads nothing, and a tree that cannot be read limits
     * every one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testManyPermissionsAreWeighedInOnePass(): void
    {
        $user    = StubIdentity::query()->create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $sources = static fn (array $policies): CheckSources => new CheckSources($policies, null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);
        $denying = self::policy([['effect' => 'deny', 'actions' => ['posts:read']]]);

        self::grants()->attachPolicy($user, self::denying('no-edit', 'posts:edit'));

        $each = ['posts:edit' => $sources([]), 'posts:read' => $sources([$denying]), 'posts:view' => $sources([]), '7' => $sources([])];

        self::assertSame(['posts:edit' => true, 'posts:read' => true, 'posts:view' => false, '7' => false], PossessionLimits::limitedEach($subject, GrantScope::platform(), $each));

        DB::flushQueryLog();
        DB::enableQueryLog();

        self::assertSame([], PossessionLimits::limitedEach($subject, GrantScope::platform(), []));
        self::assertSame([], DB::getQueryLog());

        PossessionLimits::limitedEach($subject, GrantScope::platform(), ['posts:view' => $sources([])]);

        $one = \count(DB::getQueryLog());

        DB::flushQueryLog();

        PossessionLimits::limitedEach($subject, GrantScope::platform(), $each);

        $many = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame($one, $many);

        $this->app?->instance(TenantTree::class, new FailingTenantTree(failing: ['a']));

        $unreadable = new GrantScope(new Reference('tenant', 'a'));

        self::assertSame(['posts:view' => true, '7' => true], PossessionLimits::limitedEach($subject, $unreadable, ['posts:view' => $sources([]), '7' => $sources([])]));
    }

    /**
     * What the subject's identity holds limits it even when its principal is no
     * model, and what is stored is read from the tables `authorization.tables`
     * names, so one named there that cannot be read limits every permission.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentitysPoliciesAndTheConfiguredTablesAreRead(): void
    {
        $user    = StubIdentity::query()->create(['id' => 'user-1']);
        $sources = new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);

        self::grants()->attachPolicy($user, self::denying('no-edit', 'posts:edit'));

        $identity = new Subject(new \stdClass, $user);
        $each     = ['posts:edit' => $sources, 'posts:view' => $sources];

        self::assertSame(['posts:edit' => true, 'posts:view' => false], PossessionLimits::limitedEach($identity, GrantScope::platform(), $each));

        config(['authorization.tables.authorizable_roles' => 'missing_authorizable_roles']);

        self::assertSame(['posts:view' => true], PossessionLimits::limitedEach(new Subject($user, $user), GrantScope::platform(), ['posts:view' => $sources]));
    }

    /**
     * Determine whether anything limits the permission for the subject, given
     * the check's sources, for a grant in the scope, platform-wide unless one
     * is given.
     *
     * @param  string  $permission
     * @param  array<string, list<mixed>>  $sources
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $scope
     * @return bool
     */
    private static function limits(string $permission, array $sources = [], ?Subject $subject = null, ?GrantScope $scope = null): bool
    {
        $subject ??= new Subject(new \stdClass);

        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> $policies */
        $policies = $sources['policies'] ?? [];

        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null $guardrails */
        $guardrails = $sources['guardrails'] ?? null;

        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> $boundaries */
        $boundaries = $sources['boundaries'] ?? [];

        /** @var list<array{string, list<string>}> $session */
        $session = $sources['session'] ?? [];

        $checked = new CheckSources($policies, $guardrails, $boundaries, new CheckContext, static fn (): ?string => null, new SessionCaps($session));

        return PossessionLimits::isLimited($subject, $permission, $scope ?? GrantScope::platform(), $checked);
    }

    /**
     * Return a policy of the statements, for evaluation.
     *
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function policy(array $statements): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'policy', 'statements' => $statements]);
    }

    /**
     * Create a stored policy denying the action.
     *
     * @param  string  $name
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function denying(string $name, string $action): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'deny', 'actions' => [$action]]]]]);
    }

    /**
     * Create a stored policy allowing the action alone.
     *
     * @param  string  $name
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function allowing(string $name, string $action): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => [$action]]]]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
