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
     * An empty block, whose limits take their defaults, and whole limits of at
     * least 1, written as ints or as the environment gives whole numbers, are
     * accepted.
     *
     * @return void
     */
    public function testWholeLimitsAreAccepted(): void
    {
        QueryScopingConfigValidator::validate([]);
        QueryScopingConfigValidator::validate(['max_anchors' => 1, 'max_scopes' => 16, 'max_attachments' => 64]);
        QueryScopingConfigValidator::validate(['max_anchors' => '1', 'max_scopes' => '16', 'max_attachments' => '64']);

        self::assertSame(['max_anchors', 'max_scopes', 'max_attachments'], QueryScopingConfigValidator::LIMITS);
    }

    /**
     * Return each invalid block, with the key it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function invalidBlocks(): iterable
    {
        $whole = 'expected a whole number of at least 1, got ';

        yield 'not an array' => ['64', 'authorization.query_scoping', 'expected an array, got \'64\' (string).'];
        yield 'null' => [null, 'authorization.query_scoping', 'expected an array, got \'null\' (null).'];
        $unknown = 'unknown key \'max_classes\'; expected one of max_anchors, max_scopes, max_attachments.';

        yield 'an unknown limit' => [['max_classes' => 4], 'authorization.query_scoping.max_classes', $unknown];
        yield 'zero' => [['max_scopes' => 0], 'authorization.query_scoping.max_scopes', $whole . '0 (int).'];
        yield 'zero as a string' => [['max_scopes' => '0'], 'authorization.query_scoping.max_scopes', $whole . '\'0\' (string).'];
        yield 'negative' => [['max_anchors' => -1], 'authorization.query_scoping.max_anchors', $whole . '-1 (int).'];
        yield 'a null limit' => [['max_anchors' => null], 'authorization.query_scoping.max_anchors', $whole . '\'null\' (null).'];
        yield 'a string not a whole number' => [['max_attachments' => '12abc'], 'authorization.query_scoping.max_attachments', $whole . '\'12abc\' (string).'];
        yield 'an exponent' => [['max_attachments' => '1e3'], 'authorization.query_scoping.max_attachments', $whole . '\'1e3\' (string).'];
        yield 'a padded string' => [['max_attachments' => ' 5'], 'authorization.query_scoping.max_attachments', $whole . '\' 5\' (string).'];
        yield 'an empty string' => [['max_attachments' => ''], 'authorization.query_scoping.max_attachments', $whole . '\'\' (string).'];
        yield 'a float' => [['max_scopes' => 1.5], 'authorization.query_scoping.max_scopes', $whole . '1.5 (float).'];
        yield 'a list' => [['max_scopes' => [1]], 'authorization.query_scoping.max_scopes', $whole . '\'array\' (array).'];
    }

    /**
     * Anything else is refused under its key, saying exactly why.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidBlocks')]
    public function testAnInvalidBlockIsRefused(mixed $config, string $key, string $reason): void
    {
        try {
            QueryScopingConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("Invalid authorization config at '{$key}': {$reason}", $exception->getMessage());
            self::assertSame($key, $exception->getConfigKey());
        }
    }
}
