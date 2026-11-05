<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Tests\Feature\Stubs\StubIdentity;

/**
 * Shared checks that revoking and synchronising a role or permission by name
 * work from the grants the identity holds, when the platform and the current
 * tenant each own a row of that name and guard.
 *
 * A lookup by name in the tenant's context ranks the tenant's row first, so
 * these pin that a revocation still removes a platform grant, that a
 * synchronisation keeps it, and that a revocation reports only the grants it
 * really removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ChecksGrantsByName
{
    use ActsAsTenant;

    /**
     * In a tenant's context, revoking a name removes the platform grant the
     * identity holds although the tenant owns a row of that name.
     *
     * @return void
     */
    public function testRevokingANameInATenantRemovesThePlatformGrant(): void
    {
        [$identity, $platform] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform);

        Event::fake([static::revokedEvent()]);

        $this->revokeFrom($identity, 'editor');

        self::assertSame(0, DB::table(static::grantTable())->count());
        Event::assertDispatchedTimes(static::revokedEvent(), 1);
        Event::assertDispatched(static::revokedEvent(), static fn (object $event): bool => self::revokedRow($event)?->is($platform) === true);
    }

    /**
     * Revoking a name removes every held row of that name, the platform's and
     * the tenant's, and reports each.
     *
     * @return void
     */
    public function testRevokingANameRemovesEveryHeldRowOfThatName(): void
    {
        [$identity, $platform, $tenant] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform);
        $this->grantTo($identity, $tenant);

        Event::fake([static::revokedEvent()]);

        $this->revokeFrom($identity, 'editor');

        self::assertSame(0, DB::table(static::grantTable())->count());
        Event::assertDispatchedTimes(static::revokedEvent(), 2);
    }

    /**
     * Revoking a name the identity does not hold removes nothing and reports
     * nothing.
     *
     * @return void
     */
    public function testRevokingAnUnheldNameReportsNothing(): void
    {
        [$identity] = $this->platformAndTenantRows();

        Event::fake([static::revokedEvent()]);

        $this->revokeFrom($identity, 'editor');

        Event::assertNotDispatched(static::revokedEvent());
    }

    /**
     * Revoking a name removes a grant that has already expired as well.
     *
     * @return void
     */
    public function testRevokingANameRemovesAnExpiredGrant(): void
    {
        [$identity, $platform] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform, Carbon::now()->subHour());

        $this->revokeFrom($identity, 'editor');

        self::assertSame(0, DB::table(static::grantTable())->count());
    }

    /**
     * In a tenant's context, synchronising a name keeps the platform grant the
     * identity holds rather than replacing it with the tenant's row.
     *
     * @return void
     */
    public function testSyncingANameInATenantKeepsThePlatformGrant(): void
    {
        [$identity, $platform] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform);

        $this->syncTo($identity, ['editor']);

        self::assertSame([(string) $platform->getKey()], self::grantedKeys());
    }

    /**
     * Synchronising a name the identity does not hold grants the row the lookup
     * ranks first, the tenant's.
     *
     * @return void
     */
    public function testSyncingAnUnheldNameGrantsTheRankedRow(): void
    {
        [$identity, , $tenant] = $this->platformAndTenantRows();

        $this->syncTo($identity, ['editor']);

        self::assertSame([(string) $tenant->getKey()], self::grantedKeys());
    }

    /**
     * Revoking a model removes only that row, although the identity holds
     * another of the same name.
     *
     * @return void
     */
    public function testRevokingAModelRemovesOnlyThatRow(): void
    {
        [$identity, $platform, $tenant] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform);
        $this->grantTo($identity, $tenant);

        $this->revokeFrom($identity, $platform);

        self::assertSame([(string) $tenant->getKey()], self::grantedKeys());
    }

    /**
     * Synchronising to a model keeps only that row, although the identity holds
     * another of the same name.
     *
     * @return void
     */
    public function testSyncingAModelKeepsOnlyThatRow(): void
    {
        [$identity, $platform, $tenant] = $this->platformAndTenantRows();

        $this->grantTo($identity, $platform);
        $this->grantTo($identity, $tenant);

        $this->syncTo($identity, [$tenant]);

        self::assertSame([(string) $tenant->getKey()], self::grantedKeys());
    }

    /**
     * Revoking a name no row answers is refused.
     *
     * @return void
     */
    public function testRevokingAnUnknownNameIsRefused(): void
    {
        [$identity] = $this->platformAndTenantRows();

        $this->expectException(static::unknownNameException());

        $this->revokeFrom($identity, 'director');
    }

    /**
     * Synchronising to a name no row answers is refused.
     *
     * @return void
     */
    public function testSyncingAnUnknownNameIsRefused(): void
    {
        [$identity] = $this->platformAndTenantRows();

        $this->expectException(static::unknownNameException());

        $this->syncTo($identity, ['director']);
    }

    /**
     * Return the exception a name no row answers raises.
     *
     * @return class-string<\Throwable>
     */
    abstract protected static function unknownNameException(): string;

    /**
     * Return the table the grants are written to.
     *
     * @return string
     */
    abstract protected static function grantTable(): string;

    /**
     * Return the column of the grant table that names the granted row.
     *
     * @return string
     */
    abstract protected static function targetColumn(): string;

    /**
     * Return the event a revocation dispatches.
     *
     * @return class-string
     */
    abstract protected static function revokedEvent(): string;

    /**
     * Create a row of the model under test with the given name and owner.
     *
     * @param  string  $name
     * @param  array{tenant_type: string|null, tenant_id: string|null}  $owner
     * @return \Illuminate\Database\Eloquent\Model
     */
    abstract protected static function createNamed(string $name, array $owner): Model;

    /**
     * Grant the row to the identity, until the given instant when one is given.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @param  \DateTimeInterface|null  $expiresAt
     * @return void
     */
    abstract protected function grantTo(StubIdentity $identity, Model $row, ?\DateTimeInterface $expiresAt = null): void;

    /**
     * Revoke the row, or the name, from the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model|string  $grant
     * @return void
     */
    abstract protected function revokeFrom(StubIdentity $identity, Model|string $grant): void;

    /**
     * Synchronise the identity's grants to the given rows and names.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  list<\Illuminate\Database\Eloquent\Model|string>  $grants
     * @return void
     */
    abstract protected function syncTo(StubIdentity $identity, array $grants): void;

    /**
     * Return the row a revocation event reports.
     *
     * @param  object  $event
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    abstract protected static function revokedRow(object $event): ?Model;

    /**
     * Create an identity, a platform row named `editor` for the `web` guard and
     * a row of the same name and guard owned by a tenant, and act as that
     * tenant.
     *
     * @return array{\Tests\Feature\Stubs\StubIdentity, \Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model}
     */
    private function platformAndTenantRows(): array
    {
        $tenant   = self::createTenant('tenant-a');
        $identity = StubIdentity::create(['id' => (string) Str::uuid()]);
        $platform = static::createNamed('editor', self::ownedBy(null));
        $owned    = static::createNamed('editor', self::ownedBy($tenant));

        $this->actAsTenant($tenant);

        return [$identity, $platform, $owned];
    }

    /**
     * Return the keys of the rows granted, in key order.
     *
     * @return list<string>
     */
    private static function grantedKeys(): array
    {
        /** @var list<string> */
        return DB::table(static::grantTable())->orderBy(static::targetColumn())->pluck(static::targetColumn())->map(static fn (mixed $key): string => (string) $key)->all();
    }
}
