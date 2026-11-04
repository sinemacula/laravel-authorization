<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\HasSystemProtection;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for the `HasSystemProtection` trait.
 *
 * The guard reads the persisted `is_system` flag, so clearing the flag in the
 * same update, or in memory before a delete, cannot lift the protection. Every
 * attribute of a system row other than the update timestamp is protected, and
 * the refused operation is labelled after the most significant change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(SystemRoleProtectedException::class)]
#[CoversClass(Policy::class)]
#[CoversClass(PolicyObserver::class)]
#[CoversClass(SystemPolicyProtectedException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasSystemProtection::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class HasSystemProtectionTest extends TestCase
{
    /**
     * Clean up the frozen clock after each test.
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
     * Clearing the flag in the same mass-assigned update as a rename is refused
     * as an `unprotect`, and neither change is persisted.
     *
     * @return void
     */
    public function testMassAssignedFlagClearAndRenameIsRefused(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $exception = $this->captureRoleRefusal(
            static fn () => $role->update(['is_system' => false, 'name' => 'x']),
        );

        self::assertSame('super-admin', $exception->getRoleName());
        self::assertSame('unprotect', $exception->getOperation());

        $fresh = self::reload($role);

        self::assertSame('super-admin', $fresh->name);
        self::assertTrue($fresh->is_system);
    }

    /**
     * Clearing the flag on its own is a protected change.
     *
     * @return void
     */
    public function testClearingFlagAloneIsRefused(): void
    {
        $role = $this->makeSystemRole('auditor');

        $exception = $this->captureRoleRefusal(static function () use ($role): void {
            $role->is_system = false;
            $role->save();
        });

        self::assertSame('unprotect', $exception->getOperation());
        self::assertTrue(self::reload($role)->is_system);
    }

    /**
     * Clearing the flag in memory and then deleting is refused, because the
     * persisted flag still marks the row as system.
     *
     * @return void
     */
    public function testDeleteAfterClearingFlagInMemoryIsRefused(): void
    {
        $role = $this->makeSystemRole('owner');

        $role->is_system = false;

        $exception = $this->captureRoleRefusal(static fn () => $role->delete());

        self::assertSame('owner', $exception->getRoleName());
        self::assertSame('delete', $exception->getOperation());
        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * Provide the role attributes that are not otherwise labelled, with a new
     * value for each.
     *
     * @return iterable<string, array{string, mixed}>
     */
    public static function roleFieldProvider(): iterable
    {
        yield 'description' => ['description', 'Edited.'];
        yield 'guard' => ['guard_name', 'api'];
        yield 'rank' => ['rank', 5];
    }

    /**
     * Every role attribute is protected on a system role and is refused as a
     * `modify`.
     *
     * @param  string  $field
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('roleFieldProvider')]
    public function testEveryRoleFieldIsProtected(string $field, mixed $value): void
    {
        $role = $this->makeSystemRole('super-admin');

        $exception = $this->captureRoleRefusal(static fn () => $role->update([$field => $value]));

        self::assertSame('super-admin', $exception->getRoleName());
        self::assertSame('modify', $exception->getOperation());
        self::assertSame(
            ['description' => null, 'guard_name' => 'web', 'rank' => null],
            self::reload($role)->only(['description', 'guard_name', 'rank']),
        );
    }

    /**
     * Moving a system role under a parent is a protected change.
     *
     * @return void
     */
    public function testReparentingSystemRoleIsRefused(): void
    {
        $parent = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'parent',
            'guard_name' => 'web',
        ]);

        $role = $this->makeSystemRole('child');

        $exception = $this->captureRoleRefusal(
            static fn () => $role->update(['parent_id' => $parent->getKey()]),
        );

        self::assertSame('modify', $exception->getOperation());
        self::assertNull(self::reload($role)->parent_id);
    }

    /**
     * Editing the creation timestamp is a protected change: only the update
     * timestamp is exempt.
     *
     * @return void
     */
    public function testEditingCreatedAtIsRefused(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $exception = $this->captureRoleRefusal(static function () use ($role): void {
            $role->setAttribute('created_at', Carbon::parse('2020-01-01 00:00:00'));
            $role->save();
        });

        self::assertSame('modify', $exception->getOperation());
    }

    /**
     * A rename alongside another edit is labelled `rename`.
     *
     * @return void
     */
    public function testRenameOutranksOtherEdits(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $exception = $this->captureRoleRefusal(
            static fn () => $role->update(['description' => 'Edited.', 'name' => 'renamed']),
        );

        self::assertSame('rename', $exception->getOperation());
    }

    /**
     * A rename outranks a document rewrite on a policy.
     *
     * @return void
     */
    public function testRenameOutranksDocumentRewrite(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        $exception = $this->capturePolicyRefusal(
            static fn () => $policy->update(['document' => self::denyDocument(), 'name' => 'renamed']),
        );

        self::assertSame('break-glass', $exception->getPolicyName());
        self::assertSame('rename', $exception->getOperation());
    }

    /**
     * A document rewrite alongside another edit is labelled `document-rewrite`.
     *
     * @return void
     */
    public function testDocumentRewriteOutranksOtherEdits(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        $exception = $this->capturePolicyRefusal(
            static fn () => $policy->update(['description' => 'Edited.', 'document' => self::denyDocument()]),
        );

        self::assertSame('document-rewrite', $exception->getOperation());
    }

    /**
     * Clearing the flag outranks a document rewrite on a policy.
     *
     * @return void
     */
    public function testFlagClearOutranksDocumentRewrite(): void
    {
        $policy = $this->makeSystemPolicy('break-glass');

        $exception = $this->capturePolicyRefusal(
            static fn () => $policy->update(['document' => self::denyDocument(), 'is_system' => false]),
        );

        self::assertSame('unprotect', $exception->getOperation());
    }

    /**
     * A `touch()` changes only the update timestamp and is allowed.
     *
     * @return void
     */
    public function testTouchOnSystemRoleIsAllowed(): void
    {
        Carbon::setTestNow('2026-01-01 00:00:00');

        $role = $this->makeSystemRole('super-admin');

        Carbon::setTestNow('2026-02-01 00:00:00');

        self::assertTrue($role->touch());

        $updatedAt = self::reload($role)->getAttribute('updated_at');

        self::assertInstanceOf(\DateTimeInterface::class, $updatedAt);
        self::assertSame('2026-02-01 00:00:00', $updatedAt->format('Y-m-d H:i:s'));
    }

    /**
     * A row that is not persisted as system edits freely and may be marked
     * system, after which it is protected.
     *
     * @return void
     */
    public function testRowBecomesProtectedOnceMarkedSystem(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'ordinary',
            'guard_name' => 'web',
        ]);

        $role->update(['description' => 'Edited.', 'is_system' => true]);

        self::assertSame('Edited.', self::reload($role)->description);
        self::assertTrue(self::reload($role)->is_system);

        $exception = $this->captureRoleRefusal(static fn () => $role->update(['description' => 'Again.']));

        self::assertSame('modify', $exception->getOperation());
    }

    /**
     * `forceSystem()` returns the same instance and unlocks clearing the flag
     * together with a rename.
     *
     * @return void
     */
    public function testForceSystemUnlocksFlagClearAndRename(): void
    {
        $role = $this->makeSystemRole('super-admin');

        self::assertSame($role, $role->forceSystem());

        $role->update(['is_system' => false, 'name' => 'renamed']);

        $fresh = self::reload($role);

        self::assertSame('renamed', $fresh->name);
        self::assertFalse($fresh->is_system);
    }

    /**
     * The bypass is consumed by the first protected edit, so the next one is
     * refused.
     *
     * @return void
     */
    public function testForceSystemIsConsumedByOneEdit(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $role->forceSystem()->update(['description' => 'Forced.']);

        self::assertSame('Forced.', self::reload($role)->description);

        $exception = $this->captureRoleRefusal(static fn () => $role->update(['description' => 'Again.']));

        self::assertSame('modify', $exception->getOperation());
        self::assertSame('Forced.', self::reload($role)->description);
    }

    /**
     * A save with nothing dirty clears the bypass, so it cannot unlock a later
     * edit.
     *
     * @return void
     */
    public function testCleanSaveClearsBypass(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $role->forceSystem();

        self::assertTrue($role->save());

        $exception = $this->captureRoleRefusal(static fn () => $role->update(['description' => 'Edited.']));

        self::assertSame('modify', $exception->getOperation());
    }

    /**
     * A `touch()` clears the bypass, so it cannot unlock a later delete.
     *
     * @return void
     */
    public function testTouchClearsBypass(): void
    {
        $role = $this->makeSystemRole('super-admin');

        $role->forceSystem()->touch();

        $exception = $this->captureRoleRefusal(static fn () => $role->delete());

        self::assertSame('delete', $exception->getOperation());
    }

    /**
     * Run the callback and return the system-role refusal it raises.
     *
     * @param  callable(): mixed  $callback
     * @return \SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException
     */
    private function captureRoleRefusal(callable $callback): SystemRoleProtectedException
    {
        try {
            $callback();
        } catch (SystemRoleProtectedException $exception) {
            return $exception;
        }

        self::fail('Expected SystemRoleProtectedException was not thrown.');
    }

    /**
     * Run the callback and return the system-policy refusal it raises.
     *
     * @param  callable(): mixed  $callback
     * @return \SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException
     */
    private function capturePolicyRefusal(callable $callback): SystemPolicyProtectedException
    {
        try {
            $callback();
        } catch (SystemPolicyProtectedException $exception) {
            return $exception;
        }

        self::fail('Expected SystemPolicyProtectedException was not thrown.');
    }

    /**
     * Load the persisted state of the role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function reload(Role $role): Role
    {
        return Role::query()->findOrFail($role->id);
    }

    /**
     * Create a system-flagged role on the `web` guard.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeSystemRole(string $name): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
            'is_system'  => true,
        ]);
    }

    /**
     * Create a system-flagged policy with a minimal valid document.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private function makeSystemPolicy(string $name): Policy
    {
        return Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => $name,
            'document' => [
                'statements' => [
                    [
                        'effect'    => 'allow',
                        'actions'   => ['*:*'],
                        'resources' => ['*'],
                    ],
                ],
            ],
            'is_system' => true,
        ]);
    }

    /**
     * Return a valid replacement document for rewrite scenarios.
     *
     * @return array<string, mixed>
     */
    private static function denyDocument(): array
    {
        return [
            'statements' => [
                [
                    'effect'    => 'deny',
                    'actions'   => ['*:*'],
                    'resources' => ['*'],
                ],
            ],
        ];
    }
}
