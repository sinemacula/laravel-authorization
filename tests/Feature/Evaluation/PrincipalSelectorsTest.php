<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Feature tests for whether a resource policy's `principals` selectors name the
 * subject of a check: its principal or identity by reference, or a role it
 * holds in the check's scope by its key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PrincipalSelectors::class)]
final class PrincipalSelectorsTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A selector names the principal, and its identity when that is another
     * model, by morph class and key; any other reference names neither.
     *
     * @return void
     */
    public function testASelectorNamesThePrincipalOrItsIdentityByReference(): void
    {
        $principal = StubSecondIdentity::create(['id' => 'p-1']);
        $identity  = StubIdentity::create(['id' => 'user-1']);
        $selectors = new PrincipalSelectors(new Subject($principal, $identity));

        self::assertTrue($selectors->isNamedByAny([$principal->getMorphClass() . ':p-1']));
        self::assertTrue($selectors->isNamedByAny(['other:1', $identity->getMorphClass() . ':user-1']));
        self::assertFalse($selectors->isNamedByAny([$identity->getMorphClass() . ':p-1', $principal->getMorphClass() . ':user-1']));
        self::assertFalse($selectors->isNamedByAny([]));
        self::assertTrue((new PrincipalSelectors(new Subject($principal)))->isNamedByAny([$principal->getMorphClass() . ':p-1']));
        self::assertTrue((new PrincipalSelectors(new Subject(new Reference('user', '7'))))->isNamedByAny(['user:7']));
    }

    /**
     * A subject with no morph class or key, or an empty one, has no reference a
     * selector can name.
     *
     * @return void
     */
    public function testASubjectWithoutAReferenceIsNamedByNone(): void
    {
        self::assertFalse((new PrincipalSelectors(new Subject(new \stdClass)))->isNamedByAny([\stdClass::class . ':1']));
        self::assertFalse((new PrincipalSelectors(new Subject(new StubIdentity)))->isNamedByAny([(new StubIdentity)->getMorphClass() . ':']));
        self::assertFalse((new PrincipalSelectors(new Subject(new Reference('', '7'))))->isNamedByAny([':7']));
    }

    /**
     * A role selector names whoever holds the role with that key, the principal
     * or its identity, in the current tenant and application; a role held
     * elsewhere, or not held, names no one.
     *
     * @return void
     */
    public function testARoleSelectorNamesAHolderOfTheRoleInTheScope(): void
    {
        $tenant    = self::createTenant('tenant-a');
        $editor    = Role::create(['name' => 'editor']);
        $viewer    = Role::create(['name' => 'viewer']);
        $principal = StubSecondIdentity::create(['id' => 'p-1']);
        $identity  = StubIdentity::create(['id' => 'user-1']);

        $identity->assignRole($editor, null, $tenant);
        $principal->assignRole($viewer, application: 'admin');

        $subject = new Subject($principal, $identity);

        self::assertFalse(self::isNamed($subject, ['role:' . $editor->id]));
        self::assertTrue(TenantScope::within($tenant, null, static fn (): bool => self::isNamed($subject, ['role:' . $editor->id])));
        self::assertFalse(self::isNamed($subject, ['role:' . $viewer->id]));
        self::assertTrue(TenantScope::within(null, 'admin', static fn (): bool => self::isNamed($subject, ['role:missing', 'role:' . $viewer->id])));
        self::assertFalse(TenantScope::within($tenant, 'admin', static fn (): bool => self::isNamed($subject, ['role:missing', 'role:'])));
    }

    /**
     * With the hierarchy enabled, a role selector names whoever holds a role
     * below it, as the role's permissions and policies reach them; a role below
     * the one held names no one.
     *
     * @return void
     */
    public function testARoleSelectorNamesAHolderOfARoleBelowIt(): void
    {
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $chief  = Role::create(['name' => 'chief', 'parent_id' => $editor->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->assignRole($editor);

        $subject = new Subject($user);

        self::assertTrue(self::isNamed($subject, ['role:' . $author->id]));
        self::assertTrue(self::isNamed($subject, ['role:' . $editor->id]));
        self::assertFalse(self::isNamed($subject, ['role:' . $chief->id]));
    }

    /**
     * With the hierarchy disabled, a role selector names only whoever holds
     * that role itself.
     *
     * @return void
     */
    public function testARoleSelectorNamesOnlyAHolderOfTheRoleWithoutTheHierarchy(): void
    {
        config()->set('authorization.hierarchy.enabled', false);

        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->assignRole($editor);

        $subject = new Subject($user);

        self::assertFalse(self::isNamed($subject, ['role:' . $author->id]));
        self::assertTrue(self::isNamed($subject, ['role:' . $editor->id]));
    }

    /**
     * The roles are read once for the check, and only when a role selector is
     * reached before any selector names the subject by reference.
     *
     * @return void
     */
    public function testReadsTheRolesOnceAndOnlyWhenNeeded(): void
    {
        $editor    = Role::create(['name' => 'editor']);
        $user      = StubIdentity::create(['id' => 'user-1']);
        $selectors = new PrincipalSelectors(new Subject($user));

        $user->assignRole($editor);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue($selectors->isNamedByAny([$user->getMorphClass() . ':user-1', 'role:' . $editor->id]));
        self::assertFalse($selectors->isNamedByAny(['user:2']));

        $before = \count(DB::getQueryLog());

        self::assertTrue($selectors->isNamedByAny(['role:' . $editor->id]));
        self::assertFalse($selectors->isNamedByAny(['role:other']));
        self::assertSame([0, 1], [$before, \count(DB::getQueryLog())]);

        DB::disableQueryLog();
    }

    /**
     * A grantee whose roles do not come through a `roles()` relation holds none
     * a selector can name.
     *
     * @return void
     */
    public function testAGranteeWithoutARolesRelationHoldsNoRole(): void
    {
        self::assertFalse((new PrincipalSelectors(new Subject(new RolesOnlyPrincipal)))->isNamedByAny(['role:editor']));
    }

    /**
     * Determine whether any of the selectors names the subject, through a new
     * set of its selectors.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<string>  $selectors
     * @return bool
     */
    private static function isNamed(Subject $subject, array $selectors): bool
    {
        return (new PrincipalSelectors($subject))->isNamedByAny($selectors);
    }
}
