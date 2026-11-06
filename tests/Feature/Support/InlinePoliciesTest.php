<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the rules an inline policy keeps about the grantee it
 * belongs to: its owner columns, the grantees it may be attached to, and its
 * deletion with the grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InlinePolicies::class)]
final class InlinePoliciesTest extends TestCase
{
    /**
     * A model without soft deletes is always deleted for good, and a soft
     * deleting one only while it is force deleted.
     *
     * @return void
     */
    public function testOnlyAForceDeleteOrAModelWithoutSoftDeletesIsForGood(): void
    {
        $soft = new NumberedIdentity;

        self::assertTrue(InlinePolicies::isDeletedForGood(new StubIdentity));
        self::assertFalse(InlinePolicies::isDeletedForGood($soft));

        (fn () => $this->forceDeleting = true)->call($soft);

        self::assertTrue(InlinePolicies::isDeletedForGood($soft));
    }

    /**
     * An inline policy's owner is read from its owner columns; a managed policy
     * has none.
     *
     * @return void
     */
    public function testTheOwnerIsReadFromTheOwnerColumns(): void
    {
        $inline  = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '7']);
        $managed = self::policy('shared');

        self::assertEquals(new Reference('user', '7'), InlinePolicies::ownerOf($inline));
        self::assertNull(InlinePolicies::ownerOf($managed));
    }

    /**
     * A policy with one owner column and not the other is refused, naming the
     * missing column.
     *
     * @return void
     */
    public function testAHalfSetOwnerIsRefused(): void
    {
        foreach (['owner_type' => 'owner_id', 'owner_id' => 'owner_type'] as $set => $missing) {
            try {
                InlinePolicies::assertValid(new Policy(['name' => 'half', $set => 'value']));
                self::fail('A half-set owner was accepted.');
            } catch (InvalidPolicyOwnerException $exception) {
                self::assertSame('half', $exception->getPolicyName());
                self::assertSame($missing, $exception->getMissingColumn());
            }
        }

        $managed = new Policy(['name' => 'managed']);
        $inline  = new Policy(['name' => 'inline', 'owner_type' => 'user', 'owner_id' => '1']);

        InlinePolicies::assertValid($managed);
        InlinePolicies::assertValid($inline);

        self::assertNull(InlinePolicies::ownerOf($managed));
        self::assertEquals(new Reference('user', '1'), InlinePolicies::ownerOf($inline));
        self::assertNull(InlinePolicies::ownerOf(new Policy(['owner_type' => 'user'])));
        self::assertNull(InlinePolicies::ownerOf(new Policy(['owner_id' => '1'])));
    }

    /**
     * The grantee an inline policy belongs to is fixed once it is created, and
     * a managed policy cannot become inline.
     *
     * @return void
     */
    public function testTheOwnerIsFixedOnceCreated(): void
    {
        $inline  = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '1']);
        $typed   = self::policy('typed', ['owner_type' => 'user', 'owner_id' => '1']);
        $managed = self::policy('shared');

        $inline->forceFill(['owner_id' => '2']);
        $typed->forceFill(['owner_type' => 'team']);
        $managed->forceFill(['owner_type' => 'user', 'owner_id' => '2']);

        foreach ([$inline, $typed, $managed] as $policy) {
            try {
                InlinePolicies::assertValid($policy);
                self::fail('A changed owner was accepted.');
            } catch (OwnerChangedException $exception) {
                self::assertSame('policy', $exception->getKind());
                self::assertSame($policy->name, $exception->getName());
                self::assertSame('grantee', $exception->getOwnerKind());
            }
        }
    }

    /**
     * An inline policy is never a system policy, created so or flagged later; a
     * managed policy may be one.
     *
     * @return void
     */
    public function testAnInlinePolicyIsNeverASystemPolicy(): void
    {
        $flagged = self::policy('flagged', ['owner_type' => 'user', 'owner_id' => '1']);

        $flagged->forceFill(['is_system' => true]);

        foreach ([new Policy(['name' => 'created', 'is_system' => true, 'owner_type' => 'user', 'owner_id' => '1']), $flagged] as $policy) {
            try {
                InlinePolicies::assertValid($policy);
                self::fail('A system inline policy was accepted.');
            } catch (SystemInlinePolicyException $exception) {
                self::assertSame($policy->name, $exception->getPolicyName());
            }
        }

        InlinePolicies::assertValid(new Policy(['name' => 'platform', 'is_system' => true]));
        InlinePolicies::assertValid(new Policy(['name' => 'plain', 'is_system' => false, 'owner_type' => 'user', 'owner_id' => '1']));
    }

    /**
     * The grantee an inline policy belongs to is read from its stored row, so a
     * policy loaded without its owner columns, or with them changed and not
     * saved, is refused for another grantee, and a policy whose row is gone is
     * refused.
     *
     * @return void
     */
    public function testTheGranteeIsReadFromTheStoredRow(): void
    {
        $inline  = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '1']);
        $partial = Policy::query()->select(['id', 'name'])->whereKey($inline->id)->sole();
        $changed = Policy::query()->whereKey($inline->id)->sole()->forceFill(['owner_type' => 'user', 'owner_id' => '2']);

        foreach (['partially loaded' => $partial, 'changed in memory' => $changed] as $case => $policy) {
            try {
                InlinePolicies::assertAttachable($policy, new Reference('user', '2'));
                self::fail("An inline policy {$case} was attachable to another grantee.");
            } catch (InlinePolicyAttachmentException $exception) {
                self::assertEquals(new Reference('user', '1'), $exception->getOwner(), $case);
            }
        }

        InlinePolicies::assertAttachable($changed, new Reference('user', '1'));

        DB::table('policies')->where('id', $inline->id)->delete();

        $this->expectException(InvalidGrantTargetException::class);

        InlinePolicies::assertAttachable($inline, new Reference('user', '1'));
    }

    /**
     * The stored read returns a policy's name and owner columns as stored, and
     * null for a key no policy has.
     *
     * @return void
     */
    public function testTheStoredReadReturnsTheOwnerColumns(): void
    {
        $inline = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '1']);
        $stored = InlinePolicies::stored($inline->id);

        self::assertInstanceOf(Policy::class, $stored);
        self::assertSame(['id' => $inline->id, 'name' => 'mine', 'owner_type' => 'user', 'owner_id' => '1'], $stored->getAttributes());
        self::assertNull(InlinePolicies::stored('00000000-0000-0000-0000-000000000000'));
        self::assertNull(InlinePolicies::stored(null));
        self::assertNull(InlinePolicies::stored([$inline->id]));
    }

    /**
     * The attachments query keeps the rows of a managed policy and of an inline
     * policy attached to its own grantee, and leaves out an inline policy
     * attached to a grantee of the same type with another key, or of another
     * type with the same key.
     *
     * @return void
     */
    public function testTheAttachmentsQueryLeavesOutAnotherGranteesInlinePolicy(): void
    {
        $inline  = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '1']);
        $managed = self::policy('shared');

        // Rows the write paths refuse, written past them.
        DB::table('authorizable_policies')->insert([
            ['policy_id' => $inline->id, 'authorizable_type' => 'user', 'authorizable_id' => '1'],
            ['policy_id' => $inline->id, 'authorizable_type' => 'user', 'authorizable_id' => '2'],
            ['policy_id' => $inline->id, 'authorizable_type' => 'team', 'authorizable_id' => '1'],
            ['policy_id' => $managed->id, 'authorizable_type' => 'team', 'authorizable_id' => '2'],
        ]);

        $rows = InlinePolicies::attachedToTheirGrantee(DB::table('authorizable_policies'), 'authorizable_policies')
            ->orderBy('authorizable_type')
            ->get(['policy_id', 'authorizable_type', 'authorizable_id'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();

        self::assertSame([
            ['policy_id' => $managed->id, 'authorizable_type' => 'team', 'authorizable_id' => '2'],
            ['policy_id' => $inline->id, 'authorizable_type' => 'user', 'authorizable_id' => '1'],
        ], $rows);
    }

    /**
     * An inline policy is attachable to its own grantee alone; a managed
     * policy, and anything that is not a policy, to anyone.
     *
     * @return void
     */
    public function testAnInlinePolicyIsAttachableToItsGranteeAlone(): void
    {
        $inline = self::policy('mine', ['owner_type' => 'user', 'owner_id' => '1']);

        InlinePolicies::assertAttachable($inline, new Reference('user', '1'));
        InlinePolicies::assertAttachable(self::policy('shared'), new Reference('user', '2'));
        InlinePolicies::assertAttachable(Permission::create(['name' => 'posts:read']), new Reference('user', '2'));

        foreach ([new Reference('user', '2'), new Reference('team', '1')] as $grantee) {
            try {
                InlinePolicies::assertAttachable($inline, $grantee);
                self::fail('An inline policy was attachable to another grantee.');
            } catch (InlinePolicyAttachmentException $exception) {
                self::assertSame('mine', $exception->getPolicyName());
                self::assertEquals(new Reference('user', '1'), $exception->getOwner());
                self::assertEquals($grantee, $exception->getGrantee());
            }
        }
    }

    /**
     * Deleting a grantee's inline policies deletes each through the model, so
     * each is reported with the grantees it was attached to and takes its
     * attachments with it, and leaves every other policy alone.
     *
     * @return void
     */
    public function testDeletingAGranteesInlinePolicies(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $other = StubIdentity::create(['id' => 'user-2']);
        $kept  = self::policy('kept', ['owner_type' => $other->getMorphClass(), 'owner_id' => 'user-2']);
        $mine  = [
            self::policy('first', ['owner_type' => $user->getMorphClass(), 'owner_id' => 'user-1']),
            self::policy('second', ['owner_type' => $user->getMorphClass(), 'owner_id' => 'user-1']),
        ];

        self::policy('shared');
        $user->attachPolicy($mine[0]);

        self::assertSame(2, InlinePolicies::countOwnedBy(Reference::of($user)));

        Event::fake([PolicyDeleted::class]);

        self::assertSame(2, InlinePolicies::deleteOwnedBy($user));
        self::assertSame(0, InlinePolicies::deleteOwnedBy(Reference::of($user)));

        $deleted = [];

        Event::assertDispatched(PolicyDeleted::class, static function (PolicyDeleted $event) use (&$deleted): bool {
            $deleted[$event->name] = $event->grantees;

            return true;
        });

        self::assertEquals(['first' => [Reference::of($user)], 'second' => []], $deleted);
        self::assertSame(['kept', 'shared'], Policy::query()->orderBy('name')->pluck('name')->all());
        self::assertSame(0, DB::table('authorizable_policies')->count());
        self::assertSame(1, InlinePolicies::countOwnedBy(Reference::of($other)));
        self::assertTrue($kept->exists);
    }

    /**
     * A role owns inline policies as an identity does, and they go with it.
     *
     * @return void
     */
    public function testARolesInlinePoliciesGoWithIt(): void
    {
        $role = Role::create(['name' => 'editor']);

        $role->attachPolicy($role->createInlinePolicy('editors', ['version' => 1, 'statements' => []]));
        $role->delete();

        self::assertSame(0, Policy::query()->count());
        self::assertSame(0, DB::table('authorizable_policies')->count());
    }

    /**
     * Create a policy that allows nothing, with the given extra columns.
     *
     * @param  string  $name
     * @param  array<string, string>  $columns
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $columns = []): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['version' => 1, 'statements' => []]] + $columns);
    }
}
