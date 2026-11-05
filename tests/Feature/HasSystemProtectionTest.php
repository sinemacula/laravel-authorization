<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\HasSystemProtection;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Fixtures\ExtendedRole;
use Tests\Fixtures\QueryRecorder;
use Tests\Fixtures\QueryRecordingRole;
use Tests\TestCase;

/**
 * Feature coverage for the `HasSystemProtection` trait.
 *
 * The guard reads the persisted `is_system` flag, so clearing the flag in the
 * same update, or in memory before a delete, cannot lift the protection. Every
 * attribute of a system row other than the update timestamp is protected, and
 * the refused operation is labelled after the most significant change.
 *
 * Each change `forceSystem()` unlocks is reported with `SystemOverrideUsed`,
 * once the write commits, for the operation the write belongs to.
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
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasSystemProtection::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class HasSystemProtectionTest extends TestCase
{
    use ReadsDispatchedEvents;

    /**
     * Clean up the frozen clock after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        QueryRecorder::reset();

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
        yield 'guard' => ['guard', 'api'];
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
            ['description' => null, 'guard' => 'web', 'rank' => null],
            self::reload($role)->only(['description', 'guard', 'rank']),
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
            'id'    => (string) Str::uuid(),
            'name'  => 'parent',
            'guard' => 'web',
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
            'id'    => (string) Str::uuid(),
            'name'  => 'ordinary',
            'guard' => 'web',
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
     * An override that is used is reported once the change is written: the
     * record, its name before the change, its tenant and the change allowed,
     * for the same operation as the record's own event.
     *
     * @return void
     */
    public function testAnOverrideThatIsUsedIsReported(): void
    {
        $role = $this->makeSystemRole('super-admin');

        Event::fake([SystemOverrideUsed::class, RoleUpdated::class]);

        $role->forceSystem()->update(['name' => 'renamed']);

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);
        Event::assertDispatched(SystemOverrideUsed::class, static fn (SystemOverrideUsed $event): bool => $event->record->id === $role->id
            && $event->record->type                                                                                          === $role->getMorphClass()
            && $event->name                                                                                                  === 'super-admin'
            && $event->tenant                                                                                                === null
            && $event->protectedOperation                                                                                    === 'rename'
            && $event->operation->actor                                                                                      === null);

        self::assertSame(self::dispatchedEvents(SystemOverrideUsed::class)[0]->operation->id, self::dispatchedEvents(RoleUpdated::class)[0]->operation->id);
    }

    /**
     * A forced delete of a tenant's system policy is reported as a delete,
     * naming the tenant.
     *
     * @return void
     */
    public function testAForcedDeleteIsReported(): void
    {
        $policy = Policy::create([
            'name'        => 'root',
            'document'    => ['statements' => [['effect' => 'allow', 'actions' => ['*:*']]]],
            'tenant_type' => 'stub_tenant',
            'tenant_id'   => 'tenant-a',
        ]);

        $policy->forceFill(['is_system' => true])->forceSystem()->save();

        Event::fake([SystemOverrideUsed::class]);

        $policy->forceSystem()->delete();

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);
        Event::assertDispatched(SystemOverrideUsed::class, static fn (SystemOverrideUsed $event): bool => $event->protectedOperation === 'delete'
            && $event->record->id                                                                                                    === $policy->id
            && $event->tenant?->type                                                                                                 === 'stub_tenant'
            && $event->tenant->id                                                                                                    === 'tenant-a');
    }

    /**
     * An override used through a management service names the service call's
     * actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOverrideUsedThroughAServiceNamesTheActor(): void
    {
        $role  = $this->makeSystemRole('super-admin');
        $actor = new Reference('user', 'admin-1');

        Event::fake([SystemOverrideUsed::class]);

        app(RoleService::class)->describe($role->forceSystem(), 'Forced.', $actor);

        Event::assertDispatched(SystemOverrideUsed::class, static fn (SystemOverrideUsed $event): bool => $event->operation->actor === $actor
            && $event->protectedOperation                                                                                          === 'modify');
    }

    /**
     * An unlock that no change uses, a refused change and an edit of a record
     * that is not system report nothing.
     *
     * @return void
     */
    public function testNothingIsReportedWhenNoOverrideIsUsed(): void
    {
        $role     = $this->makeSystemRole('super-admin');
        $ordinary = Role::query()->create(['name' => 'editor']);

        Event::fake([SystemOverrideUsed::class]);

        $role->forceSystem()->touch();
        $this->captureRoleRefusal(static fn () => $role->update(['description' => 'Refused.']));
        $ordinary->forceSystem()->update(['description' => 'Edited.']);
        $ordinary->delete();

        Event::assertNotDispatched(SystemOverrideUsed::class);
    }

    /**
     * An override whose write rolls back is never reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOverrideRolledBackIsNeverReported(): void
    {
        $role = $this->makeSystemRole('super-admin');

        Event::fake([SystemOverrideUsed::class]);

        try {
            DB::transaction(static function () use ($role): never {
                $role->forceSystem()->delete();

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The enclosing transaction rolled back.
        }

        Event::assertNotDispatched(SystemOverrideUsed::class);
        self::assertTrue(Role::query()->whereKey($role->id)->exists());
    }

    /**
     * An override a failed write consumed is not reported by a later save or
     * delete of the record that used none.
     *
     * @return void
     */
    public function testAnOverrideAFailedWriteConsumedIsNotReportedLater(): void
    {
        $saved   = $this->makeSystemRole('super-admin');
        $deleted = $this->makeSystemRole('auditor');
        $failing = new \ArrayObject;

        Role::updated(static function (Role $role) use ($failing): void {
            if (!$failing->offsetExists($role->id)) {
                return;
            }

            $failing->offsetUnset($role->id);

            throw new \RuntimeException('The write failed.');
        });

        foreach ([$saved, $deleted] as $role) {
            $failing->offsetSet($role->id, true);

            rescue(static fn (): bool => $role->forceSystem()->update(['is_system' => false]), null, false);

            self::assertFalse($failing->offsetExists($role->id));

            $role->refresh();
        }

        Event::fake([SystemOverrideUsed::class]);

        $saved->update(['description' => 'Edited.']);
        $deleted->delete();

        Event::assertNotDispatched(SystemOverrideUsed::class);
    }

    /**
     * Outside a service call, each save or delete of a record is an operation
     * of its own, though it is made on the same instance.
     *
     * @return void
     */
    public function testEachWriteOutsideACallIsAnOperationOfItsOwn(): void
    {
        Event::fake([RoleCreated::class, RoleUpdated::class, RoleDeleted::class]);

        $role = Role::query()->create(['name' => 'editor']);

        $role->update(['description' => 'Edited.']);
        $role->delete();

        $ids = [
            self::dispatchedEvents(RoleCreated::class)[0]->operation->id,
            self::dispatchedEvents(RoleUpdated::class)[0]->operation->id,
            self::dispatchedEvents(RoleDeleted::class)[0]->operation->id,
        ];

        self::assertCount(3, \array_unique($ids));
    }

    /**
     * A system role loaded without the `is_system` column cannot be deleted:
     * the guard reads the flag from the database.
     *
     * @return void
     */
    public function testPartiallyLoadedSystemRoleDeleteIsRefused(): void
    {
        $role    = $this->makeSystemRole('super-admin');
        $partial = Role::query()->select(['id', 'name'])->findOrFail($role->id);

        $exception = $this->captureRoleRefusal(static fn () => $partial->delete());

        self::assertSame('super-admin', $exception->getRoleName());
        self::assertSame('delete', $exception->getOperation());
        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * A system role loaded without the `is_system` column cannot be renamed.
     *
     * @return void
     */
    public function testPartiallyLoadedSystemRoleRenameIsRefused(): void
    {
        $role    = $this->makeSystemRole('super-admin');
        $partial = Role::query()->select(['id', 'name'])->findOrFail($role->id);

        $exception = $this->captureRoleRefusal(static fn () => $partial->update(['name' => 'renamed']));

        self::assertSame('rename', $exception->getOperation());
        self::assertSame('super-admin', self::reload($role)->name);
    }

    /**
     * An ordinary role loaded without the `is_system` column still edits and
     * deletes freely once the database confirms it is not a system row.
     *
     * @return void
     */
    public function testPartiallyLoadedOrdinaryRoleEditsFreely(): void
    {
        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'ordinary',
            'guard' => 'web',
        ]);

        $partial = Role::query()->select(['id', 'name'])->findOrFail($role->id);

        self::assertTrue($partial->update(['name' => 'renamed']));
        self::assertSame('renamed', self::reload($role)->name);

        self::assertTrue($partial->delete());
        self::assertNull(Role::query()->find($role->getKey()));
    }

    /**
     * The flag of a record loaded without the `is_system` column is read on the
     * write connection, so a lagging read replica cannot report a stale value
     * and lift the protection.
     *
     * @return void
     */
    public function testPartiallyLoadedFlagIsReadOnWriteConnection(): void
    {
        $role    = $this->makeSystemRole('super-admin');
        $partial = QueryRecordingRole::query()->select(['id', 'name'])->findOrFail($role->id);

        QueryRecorder::reset();

        $this->captureRoleRefusal(static fn () => $partial->delete());

        $queries = QueryRecorder::recorded();

        self::assertCount(1, $queries);
        self::assertTrue($queries[0]->useWritePdo);
    }

    /**
     * A system role loaded without its name is still refused with the
     * protection exception, which names the role by its key rather than by the
     * attempted rename.
     *
     * @return void
     */
    public function testSystemRoleLoadedWithoutNameIsNamedByKey(): void
    {
        $role    = $this->makeSystemRole('super-admin');
        $partial = Role::query()->select(['id'])->findOrFail($role->id);

        $exception = $this->captureRoleRefusal(static fn () => $partial->update(['name' => 'renamed']));

        self::assertSame($role->id, $exception->getRoleName());
        self::assertSame('rename', $exception->getOperation());
        self::assertSame('super-admin', self::reload($role)->name);
    }

    /**
     * A system record with an integer key, loaded without its name, is named by
     * the key as a string.
     *
     * @return void
     */
    public function testIntegerKeyIsReportedAsString(): void
    {
        $role = new Role;

        $role->setRawAttributes(['id' => 42, 'is_system' => true], true);

        $role->exists = true;

        $exception = $this->captureRoleRefusal(static fn () => $role->delete());

        self::assertSame('42', $exception->getRoleName());
    }

    /**
     * A system role loaded without its name or key is still refused with the
     * protection exception, which reports it as unnamed.
     *
     * @return void
     */
    public function testSystemRoleLoadedWithoutNameOrKeyIsUnnamed(): void
    {
        $role    = $this->makeSystemRole('super-admin');
        $partial = Role::query()->select(['guard'])->whereKey($role->id)->firstOrFail();

        $exception = $this->captureRoleRefusal(static fn () => $partial->delete());

        self::assertSame('[unnamed]', $exception->getRoleName());
        self::assertSame('delete', $exception->getOperation());
        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * A role loaded without its key or the `is_system` column cannot be matched
     * to a row, so the guard fails closed and refuses the delete.
     *
     * @return void
     */
    public function testRoleLoadedWithoutKeyIsRefused(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'ordinary',
            'guard' => 'web',
        ]);

        $partial = Role::query()->select(['name'])->where('name', 'ordinary')->firstOrFail();

        $exception = $this->captureRoleRefusal(static fn () => $partial->delete());

        self::assertSame('ordinary', $exception->getRoleName());
        self::assertSame('delete', $exception->getOperation());
        self::assertSame(1, Role::query()->where('name', 'ordinary')->count());
    }

    /**
     * A loaded system role stays protected even when the stored flag has since
     * been cleared elsewhere: the loaded flag is trusted without a re-read.
     *
     * @return void
     */
    public function testLoadedSystemFlagIsTrustedOverStoredValue(): void
    {
        $role   = $this->makeSystemRole('super-admin');
        $loaded = self::reload($role);

        Role::query()->whereKey($role->id)->toBase()->update(['is_system' => false]);

        $exception = $this->captureRoleRefusal(static fn () => $loaded->delete());

        self::assertSame('delete', $exception->getOperation());
        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * A subclass that extends the boot hook and calls the parent keeps the
     * protection.
     *
     * @return void
     */
    public function testSubclassExtendingBootHookKeepsProtection(): void
    {
        $role = ExtendedRole::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $exception = $this->captureRoleRefusal(static fn () => $role->delete());

        self::assertSame('delete', $exception->getOperation());
        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * A subclass can run the guard from its own scope: it refuses on a system
     * row and allows on an ordinary one.
     *
     * @return void
     */
    public function testSubclassCanRunGuard(): void
    {
        $system = ExtendedRole::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $ordinary = ExtendedRole::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'ordinary',
            'guard'     => 'web',
            'is_system' => false,
        ]);

        $exception = $this->captureRoleRefusal(static fn () => self::runGuardAsSubclass($system, 'rename'));

        self::assertSame('super-admin', $exception->getRoleName());
        self::assertSame('rename', $exception->getOperation());

        self::runGuardAsSubclass($ordinary, 'rename');

        self::assertFalse(self::reload($ordinary)->is_system);
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
     * Run the protection guard on the role from the scope of the subclass
     * fixture, as a consumer's own model method would.
     *
     * @param  \Tests\Fixtures\ExtendedRole  $role
     * @param  string  $operation
     * @return void
     */
    private static function runGuardAsSubclass(ExtendedRole $role, string $operation): void
    {
        $guard = \Closure::bind(
            fn () => $this->assertSystemProtectionAllows($operation),
            $role,
            ExtendedRole::class,
        );

        $guard();
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
            'id'        => (string) Str::uuid(),
            'name'      => $name,
            'guard'     => 'web',
            'is_system' => true,
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
