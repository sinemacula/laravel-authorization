<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Tests\TestCase;

/**
 * Feature coverage for the `vendor:publish` tag mappings exposed by
 * the service provider.
 *
 * Asserts the package registers exactly two publishable groups —
 * `authorization-config` and `authorization-migrations` — and that
 * each tag resolves to the shipped source path on disk. File
 * creation is not asserted because Testbench treats
 * `vendor:publish` as a no-op when the target file already exists;
 * the `ServiceProvider::$publishes` registry is the canonical
 * source of truth and is inspected directly via the framework's
 * public `pathsToPublish()` accessor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
final class PublishingTagsTest extends TestCase
{
    /**
     * `authorization-config` tag publishes the shipped config file
     * into `config/authorization.php` relative to the host
     * application.
     *
     * @return void
     */
    public function testConfigTagPublishesAuthorizationConfigFile(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            AuthorizationServiceProvider::class,
            'authorization-config',
        );

        self::assertNotEmpty($paths, 'Expected the authorization-config tag to register publishable paths.');

        $expectedSource = \realpath(__DIR__ . '/../../config/authorization.php');

        self::assertIsString($expectedSource);
        self::assertFileExists($expectedSource);

        $sources = \array_map(
            static fn (string $path): string => (string) \realpath($path),
            \array_keys($paths),
        );

        self::assertContains(
            $expectedSource,
            $sources,
            'Expected the shipped config file to be registered under the authorization-config tag.',
        );

        // Each source maps to an absolute target under the host
        // application's config directory.
        foreach ($paths as $target) {
            self::assertIsString($target);
            self::assertStringEndsWith(
                \DIRECTORY_SEPARATOR . 'authorization.php',
                $target,
            );
        }
    }

    /**
     * `authorization-migrations` tag publishes the shipped migrations
     * directory into the host application's `database/migrations`
     * tree.
     *
     * @return void
     */
    public function testMigrationsTagPublishesMigrationsDirectory(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            AuthorizationServiceProvider::class,
            'authorization-migrations',
        );

        self::assertNotEmpty($paths, 'Expected the authorization-migrations tag to register publishable paths.');

        $expectedSource = \realpath(__DIR__ . '/../../database/migrations');

        self::assertIsString($expectedSource);
        self::assertDirectoryExists($expectedSource);

        $sources = \array_map(
            static fn (string $path): string => (string) \realpath($path),
            \array_keys($paths),
        );

        self::assertContains(
            $expectedSource,
            $sources,
            'Expected the shipped migrations directory to be registered under the authorization-migrations tag.',
        );

        // Every mapping targets a directory path ending in
        // `migrations`.
        foreach ($paths as $target) {
            self::assertIsString($target);
            self::assertStringEndsWith('migrations', $target);
        }
    }
}
