<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `RecordWriter`, which saves and deletes rows for the record
 * services in one transaction on the package's connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordWriter::class)]
final class RecordWriterTest extends TestCase
{
    use ActsAsAdministrator, CatchesRefusals, UsesAnAuthorizationConnection;

    /**
     * The row is looked up and saved inside one transaction on the package's
     * connection, with the given attributes.
     *
     * @return void
     */
    public function testSavesInsideATransactionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $base  = self::authorizationConnection()->transactionLevel();
        $level = null;

        $role = RecordWriter::save(null, PackagePermissions::ROLE_CREATE, static function () use (&$level): Role {
            $level = self::authorizationConnection()->transactionLevel();

            return new Role;
        }, ['name' => 'editor', 'rank' => 2]);

        self::assertSame($base + 1, $level);
        self::assertTrue($role->exists);
        self::assertSame(['editor', 2], [$role->name, $role->rank]);
        self::assertSame(1, self::authorizationConnection()->table('roles')->where('name', 'editor')->count());
    }

    /**
     * A record is created keyed by the id given, or by a new key when none is
     * given, with the attributes, and a delegated creation is decided before it
     * writes, as a save is: an unranked actor may not create a ranked role.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatesARecordKeyedByTheIdGiven(): void
    {
        $keyed = RecordWriter::create(null, PackagePermissions::ROLE_CREATE, new Role, '01a1b0c0-0000-7000-8000-000000000001', ['name' => 'editor']);
        $fresh = RecordWriter::create(null, PackagePermissions::ROLE_CREATE, new Role, null, ['name' => 'author', 'rank' => 4]);

        self::assertSame('01a1b0c0-0000-7000-8000-000000000001', $keyed->id);
        self::assertTrue($fresh->exists);
        self::assertNotSame($keyed->id, $fresh->id);
        self::assertSame(['editor', 'author'], [$keyed->name, Role::query()->findOrFail($fresh->id)->name]);
        self::assertSame(4, $fresh->rank);
        $admin = self::administrator(rank: null);

        $create = static fn (): Role => RecordWriter::create($admin, PackagePermissions::ROLE_CREATE, new Role, null, ['name' => 'writer', 'rank' => 1]);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::reasonOf($create));
        self::assertSame(2, Role::query()->count());
    }

    /**
     * A save the model refuses writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSaveWritesNothing(): void
    {
        Role::query()->create(['name' => 'admin', 'is_system' => true]);

        try {
            $tenantAdmin = ['name' => 'admin', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a'];

            RecordWriter::save(null, PackagePermissions::ROLE_CREATE, static fn (): Role => new Role, $tenantAdmin);
            self::fail('The save was not refused.');
        } catch (ReservedRoleNameException) {
            self::assertSame(1, DB::table('roles')->count());
        }
    }

    /**
     * The row is looked up and deleted inside one transaction.
     *
     * @return void
     */
    public function testDeletesInsideATransaction(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $base  = DB::connection()->transactionLevel();
        $level = null;

        RecordWriter::delete(null, PackagePermissions::ROLE_DELETE, static function () use (&$level, $role): Role {
            $level = DB::connection()->transactionLevel();

            return $role;
        });

        self::assertSame($base + 1, $level);
        self::assertSame(0, Role::query()->count());
    }

    /**
     * A saved model is returned as it is, and an unsaved one is refused with
     * its kind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExistingRefusesAnUnsavedModel(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        self::assertSame($role, RecordWriter::existing('role', $role));

        try {
            RecordWriter::existing('permission', new Role(['name' => 'ghost']));
            self::fail('The unsaved model was not refused.');
        } catch (UnsavedRecordException $exception) {
            self::assertSame('permission', $exception->getKind());
            self::assertSame('The permission service takes a saved permission, not an unsaved ' . Role::class . '.', $exception->getMessage());
        }
    }

    /**
     * The events a trusted save and delete dispatch carry a trusted operation
     * with no actor, under the action, once the write commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventsCarryTheTrustedOperation(): void
    {
        Event::fake([RoleCreated::class, RoleDeleted::class]);

        $role = RecordWriter::save(null, PackagePermissions::ROLE_CREATE, static fn (): Role => new Role, ['name' => 'editor']);

        RecordWriter::delete(null, PackagePermissions::ROLE_DELETE, static fn (): Role => $role);

        Event::assertDispatched(RoleCreated::class, static fn (RoleCreated $event): bool => $event->operation->actor === null
            && $event->operation->isTrusted
            && $event->operation->actions === [PackagePermissions::ROLE_CREATE]);
        Event::assertDispatched(RoleDeleted::class, static fn (RoleDeleted $event): bool => $event->operation->actions === [PackagePermissions::ROLE_DELETE]);
    }

    /**
     * A delegated save is decided once the row is looked up, inside the
     * transaction, on the definition's operation resource, which offers the
     * proposed change to policies: an actor not allowed the action is refused
     * as the decision refuses it, and one allowed it is refused as unprovable,
     * each writing nothing and reporting no change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedSaveIsDecidedBeforeItWrites(): void
    {
        Event::fake([RoleUpdated::class, AuthorizationFailed::class]);

        $admin = self::administrator([], rank: null);
        $role  = Role::query()->create(['name' => 'editor']);
        $level = null;

        self::grants()?->grantRole(StubIdentity::query()->create(['id' => 'holder']), $role);

        self::grants()?->attachPolicy(StubIdentity::query()->findOrFail('admin-1'), Policy::query()->create(['name' => 'renamer', 'document' => ['statements' => [[
            'effect'     => 'allow',
            'actions'    => [PackagePermissions::ROLE_RENAME],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.change.name' => 'writer', 'resource.role' => 'editor']],
        ]]]]));

        $refused = self::refusalOf(static fn (): Role => RecordWriter::save($admin, PackagePermissions::ROLE_RENAME, static fn (): Role => $role, ['name' => 'author']));
        $proved  = self::refusalOf(static function () use (&$level, $admin, $role): void {
            RecordWriter::save($admin, PackagePermissions::ROLE_RENAME, static function () use (&$level, $role): Role {
                $level = DB::connection()->transactionLevel();

                return $role;
            }, ['name' => 'writer']);
        });

        self::assertInstanceOf(AuthorizationException::class, $refused);
        self::assertSame(DecisionReason::CONDITION_FAILED, $refused->getReason());
        self::assertInstanceOf(AuthorizationException::class, $proved);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $proved->getReason());
        self::assertSame(DecisionStage::ADMINISTRATION, $proved->getDecision()?->stage);
        self::assertNotNull($level);
        self::assertSame('editor', Role::query()->sole()->name);
        Event::assertNotDispatched(RoleUpdated::class);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === PackagePermissions::ROLE_RENAME
            && \str_starts_with((string) $event->resource, OperationResource::TYPE . ':'));
    }

    /**
     * A delegated deletion is decided as a save is, before the row is deleted:
     * deleting a role a deny is attached to would lift the deny, so it is
     * refused as unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedDeleteIsDecidedBeforeItDeletes(): void
    {
        $admin = self::administrator(rank: null);
        $role  = Role::query()->create(['name' => 'editor']);

        self::grants()?->attachPolicy($role, Policy::query()->create(['name' => 'denying', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:*']]]]]));

        $refusal = self::refusalOf(static fn () => RecordWriter::delete($admin, PackagePermissions::ROLE_DELETE, static fn (): Role => $role));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $refusal->getReason());
        self::assertSame(1, Role::query()->count());
    }

    /**
     * A delegated save offers each proposed attribute to policies under its
     * name, whatever attributes come before it unset, so a policy conditioned
     * on a later one decides on it: the right value is allowed, and refused at
     * the administration stage, an unranked actor giving no role a rank, and
     * any other is refused as the condition refuses it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedSaveOffersEveryProposedAttribute(): void
    {
        $admin = self::administrator([], rank: null);
        $role  = Role::query()->create(['name' => 'editor']);

        self::allow($admin, PackagePermissions::ROLE_UPDATE, ['resource.change.guard' => 'web', 'resource.change.rank' => 3]);

        $find = static fn (): Role => $role;
        $save = static fn (array $attributes): \Closure => static fn (): Role => RecordWriter::save($admin, PackagePermissions::ROLE_UPDATE, $find, $attributes);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::reasonOf($save(['name' => 'editor', 'rank' => 3, 'guard' => 'web'])));
        self::assertSame(DecisionReason::CONDITION_FAILED, self::reasonOf($save(['name' => 'editor', 'rank' => 3, 'guard' => 'api'])));
        self::assertSame('editor', Role::query()->sole()->name);
    }

    /**
     * A delegated save of a policy document offers the document by its digest,
     * as it would be stored, named as the policy is, so a policy can bind the
     * right to one exact document; the rewrite allowed lifts a deny, so it is
     * refused as unprovable at the administration stage.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedSaveOffersTheDocumentsDigest(): void
    {
        $admin    = self::administrator([], rank: null);
        $policy   = Policy::query()->create(['name' => 'readers', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:edit']]]]]);
        $document = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]];
        $digest   = DocumentDigest::of(PolicyDocument::named($document, 'readers'))->digest;

        self::allow($admin, PackagePermissions::POLICY_UPDATE, ['resource.change.digest' => $digest]);

        $find = static fn (): Policy => $policy;
        $save = static fn (mixed $document): \Closure => static fn (): Policy => RecordWriter::save($admin, PackagePermissions::POLICY_UPDATE, $find, ['document' => $document]);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::reasonOf($save($document)));
        self::assertSame(DecisionReason::CONDITION_FAILED, self::reasonOf($save(['statements' => []])));
    }

    /**
     * The proposed change offers a document that cannot be read with no digest,
     * and leaves out an attribute that is not a scalar.
     *
     * @return void
     */
    public function testTheChangeOfAnUnreadableDocumentHasNoDigest(): void
    {
        $changeOf = new \ReflectionMethod(RecordWriter::class, 'changeOf');

        self::assertSame(['name' => 'readers', 'digest' => null], $changeOf->invoke(null, ['name' => 'readers', 'description' => ['not' => 'scalar'], 'document' => '{not json']));
        self::assertSame(['rank' => 2], $changeOf->invoke(null, ['rank' => 2]));
    }

    /**
     * The document a save gives a policy is offered as it would be stored,
     * named as the policy is, or by the name the save gives it; none is offered
     * for a save that gives no document, or one that cannot be read.
     *
     * @return void
     */
    public function testTheDocumentIsOfferedAsItWouldBeStored(): void
    {
        $documentOf = new \ReflectionMethod(RecordWriter::class, 'documentOf');
        $policy     = new Policy(['name' => 'readers']);
        $document   = ['statements' => []];

        self::assertSame(['statements' => [], 'name' => 'readers'], $documentOf->invoke(null, $policy, ['document' => $document]));
        self::assertSame(['statements' => [], 'name' => 'viewers'], $documentOf->invoke(null, $policy, ['name' => 'viewers', 'document' => \json_encode($document)]));
        self::assertSame(['name' => 'own', 'statements' => []], $documentOf->invoke(null, $policy, ['document' => ['name' => 'own', 'statements' => []]]));
        self::assertNull($documentOf->invoke(null, $policy, ['name' => 'readers']));
        self::assertNull($documentOf->invoke(null, $policy, ['document' => '{not json']));
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService|null
     */
    private static function grants(): ?GrantService
    {
        return GrantService::instance();
    }

    /**
     * Allow the administrator the action on any operation, when the conditions
     * hold.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $admin
     * @param  string  $action
     * @param  array<string, mixed>  $conditions
     * @return void
     *
     * @throws \Throwable
     */
    private static function allow(ActingContext $admin, string $action, array $conditions): void
    {
        $statement = ['effect' => 'allow', 'actions' => [$action], 'resources' => [OperationResource::TYPE . ':*'], 'conditions' => ['eq' => $conditions]];

        self::grants()?->attachPolicy($admin->subject->subject, Policy::query()->create(['name' => 'allows-' . $action, 'document' => ['statements' => [$statement]]]));
    }

    /**
     * Return the reason the call is refused for.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function reasonOf(\Closure $call): ?DecisionReason
    {
        $refusal = self::refusalOf($call);

        return $refusal instanceof AuthorizationException ? $refusal->getReason() : null;
    }
}
