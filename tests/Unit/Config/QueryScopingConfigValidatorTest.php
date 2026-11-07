<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\QueryScopingConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for the boot-time validation of `authorization.query_scoping`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(QueryScopingConfigValidator::class)]
final class QueryScopingConfigValidatorTest extends TestCase
{
    /**
     * No block, an empty one and whole limits of at least 1 are accepted.
     *
     * @return void
     */
    public function testWholeLimitsAreAccepted(): void
    {
        QueryScopingConfigValidator::validate([]);
        QueryScopingConfigValidator::validate(['max_anchors' => 1, 'max_scopes' => 16, 'max_attachments' => 64]);

        self::assertSame(['max_anchors', 'max_scopes', 'max_attachments'], QueryScopingConfigValidator::LIMITS);
    }

    /**
     * Return each invalid block, with the key it is refused under.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidBlocks(): iterable
    {
        yield 'not an array' => ['64', 'authorization.query_scoping'];
        yield 'an unknown limit' => [['max_classes' => 4], 'authorization.query_scoping'];
        yield 'zero' => [['max_scopes' => 0], 'authorization.query_scoping.max_scopes'];
        yield 'negative' => [['max_anchors' => -1], 'authorization.query_scoping.max_anchors'];
        yield 'a string' => [['max_attachments' => '64'], 'authorization.query_scoping.max_attachments'];
        yield 'a float' => [['max_scopes' => 1.5], 'authorization.query_scoping.max_scopes'];
    }

    /**
     * Anything else is refused under its key.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @return void
     */
    #[DataProvider('invalidBlocks')]
    public function testAnInvalidBlockIsRefused(mixed $config, string $key): void
    {
        try {
            QueryScopingConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString($key, $exception->getMessage());
        }
    }
}
