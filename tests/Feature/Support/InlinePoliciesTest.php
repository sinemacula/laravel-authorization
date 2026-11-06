<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
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
        $managed = self::policy('shared');

        $inline->forceFill(['owner_id' => '2']);
        $managed->forceFill(['owner_type' => 'user', 'owner_id' => '2']);

        foreach ([$inline, $managed] as $policy) {
            try {
                InlinePolicies::assertValid($policy);
                self::fail('A changed owner was accepted.');
            } catch (OwnerChangedException $exception) {
                self::assertSame('policy', $exception->getKind());
                self::assertSame($policy->name, $exception->getName());
            }
        }
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
