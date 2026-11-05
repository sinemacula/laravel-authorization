<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Database\Eloquent\Model;

/**
 * Shared checks that a package model or pivot names the configured
 * `authorization.connection`, and leaves the choice to Laravel when it is
 * unset.
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
     * With the setting unset, the instance's own connection is used, which is
     * null (the default connection) until Laravel sets one.
     *
     * @return void
     */
    public function testConnectionNameIsLaravelsChoiceWhenUnset(): void
    {
        $this->configureConnection(null);

        $model = static::newConnectionModel();

        self::assertNull($model->getConnectionName());

        $model->setConnection('other');

        self::assertSame('other', $model->getConnectionName());
    }

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
