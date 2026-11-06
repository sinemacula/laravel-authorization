<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grants a decision about a subject considers: its own
 * and its identity's, never while either is inactive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectGrants::class)]
final class SubjectGrantsTest extends TestCase
{
    /**
     * A role or permission held by the principal or by its identity counts; one
     * held by neither does not.
     *
     * @return void
     */
    public function testThePrincipalsAndTheIdentitysGrantsCount(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);
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
     * The identity's policies are added when it is another model, and not again
     * when the subject is its own identity.
     *
     * @return void
     */
    public function testTheIdentitysPoliciesAreAddedOnlyWhenItIsAnotherModel(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

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
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);
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
     * A principal or identity that is inactive denies everything, whatever
     * either holds.
     *
     * @return void
     */
    public function testAnInactivePrincipalOrIdentityHoldsNothing(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = SuspendableIdentity::create(['id' => 'person-1']);
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
}
