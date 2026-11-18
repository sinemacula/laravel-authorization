<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondGrantee;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SuspendableGrantee;
use Tests\TestCase;

/**
 * Feature tests for the grants a decision about a subject considers: its own
 * and its identity's, only when both are machines or neither is, and never
 * while either is inactive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectGrants::class)]
final class SubjectGrantsTest extends TestCase
{
    use ActivatesBreakGlass, AuthorizationAssertions;

    /**
     * A role or permission held by the principal or by its identity counts; one
     * held by neither does not.
     *
     * @return void
     */
    public function testThePrincipalsAndTheIdentitysGrantsCount(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);
        $subject   = new Subject($principal, $identity);

        $principal->assignRole(Role::create(['name' => 'editor']));
        $identity->assignRole(Role::create(['name' => 'staff']));
        $principal->givePermission(Permission::create(['name' => 'posts:edit']));
        $identity->givePermission(Permission::create(['name' => 'admin:read']));

        self::assertTrue(SubjectGrants::holdsRole($subject, 'editor'));
        self::assertTrue(SubjectGrants::holdsRole($subject, 'staff'));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'owner'));
        self::assertTrue(SubjectGrants::holdsPermission($subject, 'posts:edit'));
        self::assertTrue(SubjectGrants::holdsPermission($subject, 'admin:read'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'billing:read'));
        self::assertFalse(SubjectGrants::isInactive($subject));
    }

    /**
     * A principal's role, permission and policy never reach a sibling principal
     * of the same identity, through the grant helpers or a full check.
     *
     * @return void
     */
    public function testAPrincipalsGrantsNeverReachASiblingPrincipal(): void
    {
        $first   = SuspendableGrantee::create(['id' => 'account-1']);
        $second  = SuspendableGrantee::create(['id' => 'account-2']);
        $person  = StubSecondGrantee::create(['id' => 'person-1']);
        $editor  = Role::create(['name' => 'editor']);
        $own     = new Subject($first, $person);
        $sibling = new Subject($second, $person);

        $editor->givePermission(Permission::create(['name' => 'posts:edit']));
        $first->assignRole($editor);
        $first->givePermission(Permission::create(['name' => 'posts:delete']));
        $first->attachPolicy(Policy::create(['name' => 'publisher', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:publish']]]]]));

        foreach (['posts:edit', 'posts:delete', 'posts:publish'] as $action) {
            self::assertTrue(Authorization::for($own)->can($action), $action);
            self::assertFalse(Authorization::for($sibling)->can($action), $action);
        }

        self::assertFalse(SubjectGrants::holdsRole($sibling, 'editor'));
        self::assertFalse(SubjectGrants::holdsPermission($sibling, 'posts:delete'));
        self::assertNull(SubjectGrants::permissionFor($sibling, 'posts:edit'));
    }

    /**
     * The identity's policies are added when it is another model, and not again
     * when the subject is its own identity.
     *
     * @return void
     */
    public function testTheIdentitysPoliciesAreAddedOnlyWhenItIsAnotherModel(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);

        $principal->attachPolicy(Policy::create(['name' => 'account', 'document' => ['version' => 1, 'statements' => []]]));
        $identity->attachPolicy(Policy::create(['name' => 'person', 'document' => ['version' => 1, 'statements' => []]]));

        $names = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertSame(['person'], $names(SubjectGrants::identityPolicies(new Subject($principal, $identity))));
        self::assertSame([], SubjectGrants::identityPolicies(new Subject($principal, $principal)));
        self::assertSame([], SubjectGrants::identityPolicies(new Subject($principal)));
    }

    /**
     * The boundaries of the principal and of its identity both apply, the
     * identity's once, and only when it is another model.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundariesOfThePrincipalAndItsIdentityApply(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);
        $service   = BoundaryService::instance();

        self::assertNotNull($service);

        $service->set($principal, Policy::create(['name' => 'account-cap', 'document' => ['version' => 1, 'statements' => []]]));
        $service->set($identity, Policy::create(['name' => 'person-cap', 'document' => ['version' => 1, 'statements' => []]]));

        $names = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertSame(['account-cap', 'person-cap'], $names(SubjectGrants::boundaries(new Subject($principal, $identity))));
        self::assertSame(['account-cap'], $names(SubjectGrants::boundaries(new Subject($principal, $principal))));
        self::assertSame(['account-cap'], $names(SubjectGrants::boundaries(new Subject($principal))));
        self::assertSame([], SubjectGrants::boundaries(new Subject(new \stdClass)));
    }

    /**
     * An identity's permission or role granted in a tenant reaches its
     * principal only in that tenant, and its platform-wide grant everywhere.
     *
     * @return void
     */
    public function testAnIdentitysTenantGrantReachesThePrincipalOnlyInThatTenant(): void
    {
        [$tenant, $sibling] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['tenant-a', 'tenant-b']);

        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);

        Role::create(['name' => 'publisher'])->givePermission(Permission::create(['name' => 'posts:publish']));

        $identity->givePermission(Permission::create(['name' => 'posts:edit']), null, $tenant);
        $identity->assignRole('publisher', null, $tenant);
        $identity->givePermission(Permission::create(['name' => 'admin:read']));

        foreach (['tenant' => [$tenant, true], 'sibling' => [$sibling, false], 'platform' => [null, false]] as $label => [$active, $reached]) {
            $this->actingAsSubject(new Subject($principal, $identity, $active));

            self::assertSame($reached, Authorization::can('posts:edit'), $label);
            self::assertSame($reached, Authorization::can('posts:publish'), $label);
            self::assertTrue(Authorization::can('admin:read'), $label);
        }
    }

    /**
     * The permission that matches the action is named as it was granted: the
     * principal's own when it holds one, read before the identity's, else the
     * identity's, and the action itself before any pattern that covers it; none
     * when neither holds one, while either is inactive, or when the identity is
     * of the other kind.
     *
     * @return void
     */
    public function testThePermissionForTheActionIsNamedAsItWasGranted(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = SuspendableGrantee::create(['id' => 'person-1']);
        $subject   = new Subject($principal, $identity);

        $principal->givePermission(Permission::create(['name' => 'posts:*']));
        $identity->givePermission(Permission::create(['name' => 'posts:edit']));
        $identity->givePermission(Permission::create(['name' => 'admin:*']));

        self::assertSame('posts:*', SubjectGrants::permissionFor($subject, 'posts:edit'));
        self::assertSame('admin:*', SubjectGrants::permissionFor($subject, 'admin:read'));
        self::assertSame('posts:edit', SubjectGrants::permissionFor(new Subject($identity, $identity), 'posts:edit'));
        self::assertNull(SubjectGrants::permissionFor($subject, 'billing:read'));

        $identity->suspended = true;

        self::assertNull(SubjectGrants::permissionFor($subject, 'posts:edit'));

        $machine = StubMachine::create(['id' => 'svc-1']);

        self::assertNull(SubjectGrants::permissionFor(new Subject($machine, $principal), 'posts:edit'));
        self::assertNull(SubjectGrants::permissionFor(new Subject(new \stdClass), 'posts:edit'));
    }

    /**
     * A principal or identity that is inactive denies everything, whatever
     * either holds.
     *
     * @return void
     */
    public function testAnInactivePrincipalOrIdentityHoldsNothing(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = SuspendableGrantee::create(['id' => 'person-1']);
        $subject   = new Subject($principal, $identity);

        $principal->assignRole(Role::create(['name' => 'editor']));
        $principal->givePermission(Permission::create(['name' => 'posts:edit']));

        $principal->suspended = true;

        self::assertTrue(SubjectGrants::isInactive($subject));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'editor'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'posts:edit'));

        $principal->suspended = false;
        $identity->suspended  = true;

        self::assertTrue(SubjectGrants::isInactive($subject));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'editor'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'posts:edit'));
    }

    /**
     * A person's grants never reach a machine principal: the roles, permissions
     * and allow statements of a person identity count for nothing about the
     * machine, while its deny statements, its boundary and its being inactive
     * still narrow every check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonsGrantsNeverReachAMachine(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $person  = SuspendableGrantee::create(['id' => 'person-1']);
        $subject = new Subject($machine, $person);
        $service = BoundaryService::instance();

        self::assertNotNull($service);

        $person->assignRole(Role::create(['name' => 'staff']));
        $person->givePermission(Permission::create(['name' => 'admin:read']));
        $person->attachPolicy(Policy::create(['name' => 'person', 'document' => ['version' => 1, 'statements' => []]]));
        $person->attachPolicy(Policy::create(['name' => 'person-allow', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['admin:*']]]]]));
        $person->attachPolicy(Policy::create(['name' => 'person-mixed', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:*']],
            ['effect' => 'deny', 'actions' => ['exports:*']],
            ['effect' => 'allow', 'actions' => ['comments:*']],
            ['effect' => 'deny', 'actions' => ['billing:*']],
        ]]]));
        $service->set($person, Policy::create(['name' => 'person-cap', 'document' => ['version' => 1, 'statements' => []]]));

        $denials = SubjectGrants::identityPolicies($subject);

        self::assertNull(SubjectGrants::grantingIdentity($subject));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'staff'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'admin:read'));
        self::assertCount(1, $denials);
        self::assertSame('person-mixed', $denials[0]->name);
        self::assertSame([1, 3], \array_keys($denials[0]->statements));
        self::assertSame([['exports:*'], ['billing:*']], \array_values(\array_map(static fn (Statement $statement): ?array => $statement->actions, $denials[0]->statements)));
        self::assertCount(1, SubjectGrants::boundaries($subject));

        $person->suspended = true;

        self::assertTrue(SubjectGrants::isInactive($subject));
    }

    /**
     * A machine's grants never reach a person: the roles, permissions and allow
     * statements of a machine identity count for nothing about a person
     * principal, and a policy of it with no deny statement gives nothing.
     *
     * @return void
     */
    public function testAMachinesGrantsNeverReachAPerson(): void
    {
        $person  = SuspendableGrantee::create(['id' => 'account-1']);
        $machine = StubMachine::create(['id' => 'svc-1']);
        $subject = new Subject($person, $machine);

        $machine->assignRole(Role::create(['name' => 'deployer']));
        $machine->givePermission(Permission::create(['name' => 'deploys:run']));
        $machine->attachPolicy(Policy::create(['name' => 'machine', 'document' => ['version' => 1, 'statements' => []]]));

        self::assertNull(SubjectGrants::grantingIdentity($subject));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'deployer'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'deploys:run'));
        self::assertSame([], SubjectGrants::identityPolicies($subject));
    }

    /**
     * A machine identity's grants reach a machine principal, as a person
     * identity's reach a person principal; a subject that is its own identity,
     * or has none, has no other identity to grant to it.
     *
     * @return void
     */
    public function testAnIdentityOfTheSameKindGrantsToTheSubject(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $owner   = StubMachine::create(['id' => 'svc-owner']);
        $subject = new Subject($machine, $owner);

        $owner->assignRole(Role::create(['name' => 'deployer']));
        $owner->givePermission(Permission::create(['name' => 'deploys:run']));
        $owner->attachPolicy(Policy::create(['name' => 'owner', 'document' => ['version' => 1, 'statements' => []]]));

        $names = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertSame($owner, SubjectGrants::grantingIdentity($subject));
        self::assertTrue(SubjectGrants::holdsRole($subject, 'deployer'));
        self::assertTrue(SubjectGrants::holdsPermission($subject, 'deploys:run'));
        self::assertSame(['owner'], $names(SubjectGrants::identityPolicies($subject)));
        self::assertNull(SubjectGrants::grantingIdentity(new Subject($machine, $machine)));
        self::assertNull(SubjectGrants::grantingIdentity(new Subject($machine)));

        $person   = SuspendableGrantee::create(['id' => 'account-1']);
        $identity = StubSecondGrantee::create(['id' => 'person-1']);

        self::assertSame($identity, SubjectGrants::grantingIdentity(new Subject($person, $identity)));
    }

    /**
     * A subject that holds no grants is active and holds nothing.
     *
     * @return void
     */
    public function testASubjectThatCannotHoldGrantsHoldsNothing(): void
    {
        $subject = new Subject(new \stdClass);

        self::assertFalse(SubjectGrants::isInactive($subject));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'editor'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'posts:edit'));
        self::assertSame([], SubjectGrants::identityPolicies($subject));
    }

    /**
     * Each policy with a deny statement keeps its deny statements alone, at
     * their positions, with its name, version, key and resource; one with none
     * is left out.
     *
     * @return void
     */
    public function testTheDenialsOfPoliciesKeepTheirDenyStatementsAlone(): void
    {
        $allow  = new Statement(PolicyEffect::ALLOW, ['posts:view']);
        $deny   = new Statement(PolicyEffect::DENY, ['posts:edit']);
        $mixed  = new EvaluationPolicy('mixed', [$allow, $deny], 1, 'key', 'posts:*');
        $denied = SubjectGrants::denialsOf([$mixed, new EvaluationPolicy('allows', [$allow])]);

        self::assertCount(1, $denied);
        self::assertSame([1 => $deny], $denied[0]->statements);
        self::assertSame(['mixed', 1, 'key', 'posts:*'], [$denied[0]->name, $denied[0]->version, $denied[0]->id, $denied[0]->resource]);
    }

    /**
     * The identity behind a principal is marked as one once read, so none of
     * its break-glass activations reaches the principal, while the principal's
     * own does; a subject that is its own identity is never marked.
     *
     * @return void
     */
    public function testAnIdentitysActivationsNeverReachThePrincipal(): void
    {
        $principal = SuspendableGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);
        $subject   = new Subject($principal, $identity);

        self::activate($identity, self::emergencyRole('admin:read', 'staff'));
        self::activate($principal, self::emergencyRole('posts:edit', 'editor'));

        self::assertFalse(BreakGlassActivations::isIdentity($identity));
        self::assertFalse(SubjectGrants::isInactive($subject));
        self::assertTrue(BreakGlassActivations::isIdentity($identity));
        self::assertFalse(BreakGlassActivations::isIdentity($principal));
        self::assertFalse(SubjectGrants::holdsRole($subject, 'staff'));
        self::assertFalse(SubjectGrants::holdsPermission($subject, 'admin:read'));
        self::assertTrue(SubjectGrants::holdsRole($subject, 'editor'));
        self::assertTrue(SubjectGrants::holdsPermission($subject, 'posts:edit'));

        $own = new Subject($principal, $principal);

        self::assertTrue(SubjectGrants::holdsRole($own, 'editor'));
        self::assertNull(SubjectGrants::grantingIdentity($own));
        self::assertFalse(BreakGlassActivations::isIdentity($principal));
    }
}
