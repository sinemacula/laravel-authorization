<?php

declare(strict_types = 1);

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Enforces the standalone-first invariant: the runtime `require` block in
 * `composer.json` must never depend on a sibling `sinemacula/laravel-*`
 * package. Runs as part of the test suite so regressions are caught
 * locally, not only in CI.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PackageIsolationTest extends TestCase
{
    /**
     * The runtime `require` block must not contain any
     * `sinemacula/laravel-*` package entry.
     *
     * @return void
     */
    public function testRuntimeRequireHasNoSiblingLaravelPackages(): void
    {
        $manifest = $this->readComposerManifest();

        self::assertArrayHasKey('require', $manifest, 'composer.json is missing a "require" block.');
        self::assertIsArray($manifest['require'], 'composer.json "require" block must be an object.');

        // Positive-case assertion — confirms the file was parsed correctly.
        self::assertArrayHasKey('php', $manifest['require'], 'composer.json "require" block must declare a php constraint.');

        $offenders = array_values(array_filter(
            array_keys($manifest['require']),
            static fn (string $package): bool => (bool) preg_match('#^sinemacula/laravel-#', $package),
        ));

        $message = sprintf(
            'composer.json "require" block must not depend on any sinemacula/laravel-* package; '
            . 'found: %s. Move these entries to "require-dev" or remove them to preserve the '
            . 'standalone guarantee.',
            implode(', ', $offenders),
        );

        self::assertSame([], $offenders, $message);
    }

    /**
     * Read and decode the project's root composer.json manifest.
     *
     * @return array<string, mixed>
     */
    private function readComposerManifest(): array
    {
        $path = __DIR__ . '/../../composer.json';

        self::assertFileExists($path, 'composer.json not found at project root.');

        $raw = file_get_contents($path);

        self::assertIsString($raw, 'Failed to read composer.json.');

        /** @var array<string, mixed> */
        return json_decode($raw, associative: true, flags: JSON_THROW_ON_ERROR);
    }
}
