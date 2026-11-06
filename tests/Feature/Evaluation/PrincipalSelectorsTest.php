<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
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
     * A selector naming a person identity never names a machine principal, nor
     * one naming a machine identity a person, by reference or by a role the
     * identity holds; the principal itself is still named.
     *
     * @return void
     */
    public function testAnIdentityOfAnotherKindIsNamedByNone(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $person  = StubIdentity::create(['id' => 'user-1']);
        $role    = Role::create(['name' => 'staff']);

        $person->assignRole($role);
        $machine->assignRole(Role::create(['name' => 'deployer']));

        $ofMachine = new PrincipalSelectors(new Subject($machine, $person));
        $ofPerson  = new PrincipalSelectors(new Subject($person, $machine));

        self::assertFalse($ofMachine->isNamedByAny([$person->getMorphClass() . ':user-1', 'role:' . $role->id]));
        self::assertTrue($ofMachine->isNamedByAny([$machine->getMorphClass() . ':svc-1']));
        self::assertFalse($ofPerson->isNamedByAny([$machine->getMorphClass() . ':svc-1']));
        self::assertTrue($ofPerson->isNamedByAny(['role:' . $role->id]));
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
        self::assertFalse((new PrincipalSelectors(new Subject(new class {
            /**
             * Return the morph class.
             *
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'x';
            }
        })))->isNamedByAny(['x:1']));
        self::assertFalse((new PrincipalSelectors(new Subject(new class {
            /**
             * Return the key.
             *
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        })))->isNamedByAny(['x:1', ':1']));
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
        self::assertTrue(TenantScope::within($tenant, null, static fn (): bool => self::isNamed($subject, ['other:1', 'role:' . $editor->id])));
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
     * The roles are read at most once for the check, and only when a role
     * selector is reached before any selector names the subject by reference;
     * the next check, through a new set of selectors, reads them from the
     * resolution cache, running no query.
     *
     * @return void
     */
    public function testReadsTheRolesOnceAndOnlyWhenNeeded(): void
    {
        $author    = Role::create(['name' => 'author']);
        $editor    = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user      = StubIdentity::create(['id' => 'user-1']);
        $selectors = new PrincipalSelectors(new Subject($user));

        $user->assignRole($editor);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue($selectors->isNamedByAny([$user->getMorphClass() . ':user-1', 'role:' . $editor->id]));
        self::assertFalse($selectors->isNamedByAny(['user:2']));

        $before = \count(DB::getQueryLog());

        self::assertTrue($selectors->isNamedByAny(['role:' . $author->id]));

        $read = \count(DB::getQueryLog());

        self::assertFalse($selectors->isNamedByAny(['role:other']));
        self::assertTrue(self::isNamed(new Subject($user), ['role:' . $editor->id]));
        self::assertSame([0, 3, 3], [$before, $read, \count(DB::getQueryLog())]);

        DB::disableQueryLog();
    }

    /**
     * A subject with an integer key is named by its key; one whose key is
     * neither a string nor an integer has no reference, nor does one with a
     * morph class but no key, or a key but no morph class.
     *
     * @return void
     */
    public function testASubjectIsNamedByAnIntegerKeyAlone(): void
    {
        $numbered = NumberedIdentity::create(['name' => 'n']);
        $float    = new class {
            /**
             * Return the morph class.
             *
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'user';
            }

            /**
             * Return the key, a float.
             *
             * @return float
             */
            public function getKey(): float
            {
                return 1.5;
            }
        };

        self::assertIsInt($numbered->getKey());
        self::assertTrue((new PrincipalSelectors(new Subject($numbered)))->isNamedByAny([$numbered->getMorphClass() . ':' . $numbered->getKey()]));
        self::assertFalse((new PrincipalSelectors(new Subject($float)))->isNamedByAny(['user:1.5']));
    }

    /**
     * Without a resolution cache bound, the roles are read straight from the
     * database.
     *
     * @return void
     */
    public function testReadsTheRolesWithoutACache(): void
    {
        $editor = Role::create(['name' => 'editor']);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->assignRole($editor);

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertTrue(self::isNamed(new Subject($user), ['role:' . $editor->id]));
        self::assertFalse(self::isNamed(new Subject($user), ['role:other']));
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
