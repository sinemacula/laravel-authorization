<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\HeldLifetime;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Feature\Stubs\UndeclaredGrantsGrantee;
use Tests\TestCase;

/**
 * Feature tests for `HeldLifetime`, how long a subject holds a permission, or a
 * policy, in the current scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HeldLifetime::class)]
final class HeldLifetimeTest extends TestCase
{
    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A direct grant lasts until it expires, or forever, a wildcard covering
     * the permission counts, the latest grant wins, and one that has expired or
     * names another permission does not count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADirectGrantLastsUntilItExpires(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertNull(HeldLifetime::of(self::subject($user), 'posts:edit'));

        self::grants()->grantPermission($user, self::permission('posts:read'));
        self::grants()->grantPermission($user, self::permission('posts:edit'), Carbon::now()->addDay());
        self::grants()->grantPermission($user, self::permission('posts:*'), Carbon::now()->addDays(2));

        self::assertSame(Carbon::now()->addDays(2)->getTimestamp(), HeldLifetime::of(self::subject($user), 'posts:edit'));
        self::assertSame(\PHP_INT_MAX, HeldLifetime::of(self::subject($user), 'posts:read'));
        self::assertNull(HeldLifetime::of(self::subject($user), 'billing:view'));

        Carbon::setTestNow(Carbon::now()->addDays(3));

        self::assertNull(HeldLifetime::of(self::subject($user), 'posts:edit'));
    }

    /**
     * Many permissions are read in one pass, each keyed by its name, with the
     * same lifetime it has alone, directly and through a role, in the same
     * number of queries however many there are; each is unheld while the
     * subject is inactive.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testManyPermissionsAreReadInOnePass(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $editor = Role::create(['name' => 'editor']);

        self::grants()->grantPermission($user, self::permission('posts:read'));
        self::grants()->grantPermission($user, self::permission('posts:edit'), Carbon::now()->addDay());
        self::roles()->grantPermission($editor, self::permission('posts:*'), Carbon::now()->addDays(3));
        self::roles()->grantPermission($editor, self::permission('billing:view'));
        self::grants()->grantRole($user, $editor, Carbon::now()->addDays(2));

        $names    = ['posts:read', 'posts:edit', 'billing:view', 'billing:refund', '7'];
        $each     = HeldLifetime::ofEach(self::subject($user), $names);
        $expected = [];

        foreach ($names as $name) {
            $expected[$name] = HeldLifetime::of(self::subject($user), $name);
        }

        self::assertSame($expected, $each);
        self::assertSame(\PHP_INT_MAX, $each['posts:read']);
        self::assertSame(Carbon::now()->addDays(2)->getTimestamp(), $each['posts:edit']);
        self::assertSame(Carbon::now()->addDays(2)->getTimestamp(), $each['billing:view']);
        self::assertNull($each['billing:refund']);
        self::assertSame(self::queriesOf($user, ['posts:read']), self::queriesOf($user, $names));
        self::assertSame([], HeldLifetime::ofEach(self::subject($user), []));
        self::assertSame(['posts:read' => null], HeldLifetime::ofEach(new Subject(new \stdClass), ['posts:read']));

        $writer = StubIdentity::create(['id' => 'writer-1']);

        self::grants()->grantPermission($writer, self::permission('posts:write'));

        self::assertSame(['posts:archive' => null, 'posts:write' => \PHP_INT_MAX], HeldLifetime::ofEach(self::subject($writer), ['posts:archive', 'posts:write']));
    }

    /**
     * A role's grant of the permission lasts until the earlier of the role's
     * grant and the role's own, its ancestors' included while the hierarchy is
     * enabled, and only then; the latest such grant wins, among a role's own
     * grants too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolesGrantLastsUntilTheEarlierOfItsTwoGrants(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $staff  = Role::create(['name' => 'staff']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $staff->id]);
        $writer = Role::create(['name' => 'writer']);

        self::roles()->grantPermission($staff, self::permission('posts:edit'), Carbon::now()->addDays(4));
        self::roles()->grantPermission($writer, self::permission('posts:*'));
        self::grants()->grantRole($user, $editor, Carbon::now()->addDays(9));

        self::assertSame(Carbon::now()->addDays(4)->getTimestamp(), HeldLifetime::of(self::subject($user), 'posts:edit'));

        self::roles()->grantPermission($editor, self::permission('posts:e*'), Carbon::now()->addDays(5));
        self::roles()->grantPermission($editor, self::permission('*'), Carbon::now()->addDays(2));

        self::assertSame(Carbon::now()->addDays(5)->getTimestamp(), HeldLifetime::of(self::subject($user), 'posts:edit'));

        self::grants()->grantRole($user, $writer, Carbon::now()->addDays(6));

        self::assertSame(Carbon::now()->addDays(6)->getTimestamp(), HeldLifetime::of(self::subject($user), 'posts:edit'));

        config(['authorization.hierarchy.enabled' => false]);

        self::grants()->revokeRole($user, $writer);
        self::roles()->revokePermission($editor, 'posts:e*');

        self::assertSame(Carbon::now()->addDays(2)->getTimestamp(), HeldLifetime::of(self::subject($user), 'posts:edit'));
    }

    /**
     * A chain of roles that cannot be read carries nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChainThatCannotBeReadCarriesNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $one  = Role::create(['name' => 'one']);
        $two  = Role::create(['name' => 'two', 'parent_id' => $one->id]);

        self::roles()->grantPermission($two, self::permission('posts:edit'));
        self::grants()->grantRole($user, $two);

        DB::table('roles')->where('id', $one->id)->update(['parent_id' => $two->id]);

        self::assertNull(HeldLifetime::of(self::subject($user), 'posts:edit'));
    }

    /**
     * The identity's grants count when it grants to the subject, a machine's
     * never reach a person; an inactive subject holds nothing, and one whose
     * grants cannot be read holds nothing either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityCountsWhenItGrantsToTheSubject(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $identity  = StubIdentity::create(['id' => 'person-1']);
        $machine   = StubMachine::create(['id' => 'machine-1']);

        self::grants()->grantPermission($identity, self::permission('posts:edit'));
        self::grants()->grantPermission($machine, self::permission('posts:edit'));

        self::assertSame(\PHP_INT_MAX, HeldLifetime::of(new Subject($principal, $identity), 'posts:edit'));
        self::assertSame(\PHP_INT_MAX, HeldLifetime::of(new Subject(new \stdClass, $identity), 'posts:edit'));
        self::assertNull(HeldLifetime::of(new Subject($principal, $machine), 'posts:edit'));
        self::assertNull(HeldLifetime::of(new Subject(new \stdClass), 'posts:edit'));

        $suspended = SuspendableIdentity::create(['id' => 'suspended-1']);

        self::grants()->grantPermission($suspended, self::permission('posts:edit'));

        self::assertSame(\PHP_INT_MAX, HeldLifetime::of(self::subject($suspended), 'posts:edit'));

        $suspended->suspended = true;

        self::assertNull(HeldLifetime::of(self::subject($suspended), 'posts:edit'));
        self::assertSame(['posts:edit' => null, 'posts:read' => null], HeldLifetime::ofEach(self::subject($suspended), ['posts:edit', 'posts:read']));
    }

    /**
     * Only the grants that reach the scope in place count: a grant in a tenant
     * counts there, and not at platform scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheGrantsOfTheScopeCount(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = new Reference('tenant', 'a');

        self::grants()->grantPermission($user, self::permission('posts:edit'), tenant: $tenant);

        self::assertNull(HeldLifetime::of(self::subject($user), 'posts:edit'));
        self::assertSame(\PHP_INT_MAX, TenantScope::within($tenant, null, static fn (): ?int => HeldLifetime::of(self::subject($user), 'posts:edit')));
    }

    /**
     * A grantee that does not declare the contracts of its relations holds
     * nothing through them, though it has the relations and rows in them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeWithoutTheContractsHoldsNothing(): void
    {
        $bare   = UndeclaredGrantsGrantee::query()->create(['id' => 'bare']);
        $editor = Role::create(['name' => 'editor']);
        $policy = Policy::create(['name' => 'reader', 'document' => ['statements' => []]]);
        $named  = new Reference($bare->getMorphClass(), 'bare');

        self::roles()->grantPermission($editor, self::permission('posts:edit'));
        self::grants()->grantPermission($named, self::permission('posts:edit'));
        self::grants()->grantRole($named, $editor);
        self::grants()->attachPolicy($named, $policy);
        self::grants()->attachPolicy($editor, $policy);

        self::assertSame(2, DB::table('authorizable_permissions')->count() + DB::table('authorizable_roles')->count());
        self::assertNull(HeldLifetime::of(self::subject($bare), 'posts:edit'));
        self::assertSame(['posts:edit' => null, 'posts:read' => null], HeldLifetime::ofEach(self::subject($bare), ['posts:edit', 'posts:read']));
        self::assertNull(HeldLifetime::ofPolicy(self::subject($bare), $policy->id));
    }

    /**
     * A policy is held until the latest of its attachments lasts: one directly
     * to the grantee, until it expires, and one to a role, until the earlier of
     * the role's grant and the attachment, its ancestors' included; one that
     * has expired, held in another scope, or of another policy does not count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyIsHeldUntilItsLatestAttachmentLasts(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $staff  = Role::create(['name' => 'staff']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $staff->id]);
        $policy = Policy::create(['name' => 'delegates', 'document' => ['statements' => []]]);
        $other  = Policy::create(['name' => 'other', 'document' => ['statements' => []]]);

        self::assertNull(HeldLifetime::ofPolicy(self::subject($user), $policy->id));

        self::grants()->attachPolicy($user, $other);
        self::grants()->attachPolicy($user, $policy, Carbon::now()->addDay());
        self::grants()->attachPolicy($user, $policy, Carbon::now()->addDays(9), tenant: new Reference('tenant', 'a'));

        self::assertSame(Carbon::now()->addDay()->getTimestamp(), HeldLifetime::ofPolicy(self::subject($user), $policy->id));

        self::grants()->grantRole($user, $editor, Carbon::now()->addDays(4));
        self::grants()->attachPolicy($staff, $policy, Carbon::now()->addDays(3));
        self::grants()->attachPolicy($editor, $policy, Carbon::now()->addDays(2));

        self::assertSame(Carbon::now()->addDays(3)->getTimestamp(), HeldLifetime::ofPolicy(self::subject($user), $policy->id));

        self::grants()->attachPolicy($editor, $policy);

        self::assertSame(Carbon::now()->addDays(4)->getTimestamp(), HeldLifetime::ofPolicy(self::subject($user), $policy->id));

        Carbon::setTestNow(Carbon::now()->addDays(5));

        self::assertNull(HeldLifetime::ofPolicy(self::subject($user), $policy->id));
        self::assertSame(\PHP_INT_MAX, HeldLifetime::ofPolicy(self::subject($user), $other->id));
    }

    /**
     * A policy attached to a role in another tenant, or for another
     * application, does not count where it does not hold, nor once it has
     * expired, nor one attached to another kind of grantee with the role's key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolesAttachmentCountsInItsOwnScope(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $editor = Role::create(['name' => 'editor']);
        $policy = Policy::create(['name' => 'delegates', 'document' => ['statements' => []]]);
        $tenant = new Reference('tenant', 'a');

        self::grants()->grantRole($user, $editor);
        self::grants()->attachPolicy($editor, $policy, tenant: $tenant);
        self::grants()->attachPolicy($editor, $policy, application: 'admin');

        self::assertNull(HeldLifetime::ofPolicy(self::subject($user), $policy->id));
        self::assertSame(\PHP_INT_MAX, TenantScope::within($tenant, null, static fn (): ?int => HeldLifetime::ofPolicy(self::subject($user), $policy->id)));
        self::assertSame(\PHP_INT_MAX, TenantScope::within(null, 'admin', static fn (): ?int => HeldLifetime::ofPolicy(self::subject($user), $policy->id)));

        $writer = Role::create(['name' => 'writer']);

        self::grants()->grantRole($user, $writer);
        self::grants()->attachPolicy($writer, $policy, Carbon::now()->addMinute());
        self::grants()->attachPolicy(new Reference('other-type', $writer->id), $policy);

        self::assertSame(Carbon::now()->addMinute()->getTimestamp(), HeldLifetime::ofPolicy(self::subject($user), $policy->id));

        Carbon::setTestNow(Carbon::now()->addHour());

        self::assertNull(HeldLifetime::ofPolicy(self::subject($user), $policy->id));
    }

    /**
     * Return the subject of the model, as its own identity.
     *
     * @param  object  $model
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subject(object $model): Subject
    {
        return new Subject($model, $model);
    }

    /**
     * Return the platform permission of the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Count the queries reading the identity's lifetimes of the permissions
     * takes.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  list<string>  $permissions
     * @return int
     */
    private static function queriesOf(StubIdentity $user, array $permissions): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        HeldLifetime::ofEach(self::subject($user), $permissions);

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
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

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        return app(RoleService::class);
    }
}
