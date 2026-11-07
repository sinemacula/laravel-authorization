<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\BulkConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for the boot-time validation of `authorization.bulk`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BulkConfigValidator::class)]
final class BulkConfigValidatorTest extends TestCase
{
    /**
     * No block, an empty one and a whole chunk size of at least 1 are accepted.
     *
     * @return void
     */
    public function testAWholeChunkSizeIsAccepted(): void
    {
        BulkConfigValidator::validate([]);
        BulkConfigValidator::validate(['chunk_size' => 1]);
        BulkConfigValidator::validate(['chunk_size' => 500]);

        self::assertSame(['chunk_size'], BulkConfigValidator::KEYS);
        self::assertSame('authorization.bulk', BulkConfigValidator::KEY);
    }

    /**
     * Return each invalid block, with the key it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function invalidBlocks(): iterable
    {
        $whole = 'expected a whole number of at least 1, got ';

        yield 'not an array' => ['500', 'authorization.bulk', 'expected an array, got \'500\' (string).'];
        yield 'an object' => [new \stdClass, 'authorization.bulk', 'expected an array, got \'stdClass\' (stdClass).'];
        yield 'an unknown key' => [['size' => 4], 'authorization.bulk', 'unknown key \'size\'; expected one of chunk_size.'];
        yield 'zero' => [['chunk_size' => 0], 'authorization.bulk.chunk_size', $whole . '0 (int).'];
        yield 'negative' => [['chunk_size' => -1], 'authorization.bulk.chunk_size', $whole . '-1 (int).'];
        yield 'a string' => [['chunk_size' => '500'], 'authorization.bulk.chunk_size', $whole . '\'500\' (string).'];
        yield 'a float' => [['chunk_size' => 1.5], 'authorization.bulk.chunk_size', $whole . '1.5 (float).'];
        yield 'a list' => [['chunk_size' => [1]], 'authorization.bulk.chunk_size', $whole . '\'array\' (array).'];
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
            BulkConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("Invalid authorization config at '{$key}': {$reason}", $exception->getMessage());
            self::assertSame($key, $exception->getConfigKey());
        }
    }
}
