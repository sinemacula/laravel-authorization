<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * Shared checks that a package model or pivot names the configured
 * `authorization.connection`, and the application's default connection when it
 * is unset.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ChecksTheConnectionName
{
    /**
     * The configured connection wins, even over a connection Laravel set on the
     * instance, as it does on a pivot built from a grantee on another
     * connection.
     *
     * @return void
     */
    public function testConnectionNameIsTheConfiguredConnection(): void
    {
        $this->configureConnection('identity');

        $model = static::newConnectionModel();

        self::assertSame('identity', $model->getConnectionName());

        $model->setConnection('other');

        self::assertSame('identity', $model->getConnectionName());
    }

    /**
     * With the setting unset, the application's default connection is named
     * rather than left to Laravel, so a relation never hands the model or pivot
     * the connection of the model it starts from.
     *
     * @return void
     */
    public function testConnectionNameIsTheDefaultConnectionWhenUnset(): void
    {
        $this->configureConnection(null);

        self::assertSame(DB::getDefaultConnection(), static::newConnectionModel()->getConnectionName());
    }

    /**
     * With the setting unset, a model keeps a connection set on the instance,
     * as `on()` sets one; a pivot does not, since the one it carries is always
     * its parent's.
     *
     * @return void
     */
    public function testInstanceConnectionWhenUnsetIsKeptByModelsOnly(): void
    {
        $this->configureConnection(null);

        $model = static::newConnectionModel();

        $model->setConnection('other');

        self::assertSame(static::isAPivot() ? DB::getDefaultConnection() : 'other', $model->getConnectionName());
    }

    /**
     * Determine whether the class under test is a pivot.
     *
     * @return bool
     */
    abstract protected static function isAPivot(): bool;

    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    abstract protected static function newConnectionModel(): Model;

    /**
     * Set the `authorization.connection` setting.
     *
     * @param  string|null  $connection
     * @return void
     */
    private function configureConnection(?string $connection): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('authorization.connection', $connection);
    }
}
