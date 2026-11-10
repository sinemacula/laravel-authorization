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
     * An empty block, whose chunk size takes its default, and a whole chunk
     * size of at least 1, written as an int or as the environment gives a whole
     * number, are accepted.
     *
     * @return void
     */
    public function testAWholeChunkSizeIsAccepted(): void
    {
        BulkConfigValidator::validate([]);
        BulkConfigValidator::validate(['chunk_size' => 1]);
        BulkConfigValidator::validate(['chunk_size' => 500]);
        BulkConfigValidator::validate(['chunk_size' => '1']);
        BulkConfigValidator::validate(['chunk_size' => '500']);

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
        yield 'null' => [null, 'authorization.bulk', 'expected an array, got \'null\' (null).'];
        yield 'an unknown key' => [['size' => 4], 'authorization.bulk.size', 'unknown key \'size\'; expected one of chunk_size.'];
        yield 'an unknown key after a known one' => [['chunk_size' => 1, 'size' => 4], 'authorization.bulk.size', 'unknown key \'size\'; expected one of chunk_size.'];
        yield 'zero' => [['chunk_size' => 0], 'authorization.bulk.chunk_size', $whole . '0 (int).'];
        yield 'zero as a string' => [['chunk_size' => '0'], 'authorization.bulk.chunk_size', $whole . '\'0\' (string).'];
        yield 'negative' => [['chunk_size' => -1], 'authorization.bulk.chunk_size', $whole . '-1 (int).'];
        yield 'a null chunk size' => [['chunk_size' => null], 'authorization.bulk.chunk_size', $whole . '\'null\' (null).'];
        yield 'a string not a whole number' => [['chunk_size' => '12abc'], 'authorization.bulk.chunk_size', $whole . '\'12abc\' (string).'];
        yield 'an exponent' => [['chunk_size' => '1e3'], 'authorization.bulk.chunk_size', $whole . '\'1e3\' (string).'];
        yield 'a padded string' => [['chunk_size' => ' 5'], 'authorization.bulk.chunk_size', $whole . '\' 5\' (string).'];
        yield 'a decimal string' => [['chunk_size' => '5.0'], 'authorization.bulk.chunk_size', $whole . '\'5.0\' (string).'];
        yield 'an empty string' => [['chunk_size' => ''], 'authorization.bulk.chunk_size', $whole . '\'\' (string).'];
        yield 'a boolean' => [['chunk_size' => true], 'authorization.bulk.chunk_size', $whole . 'true (bool).'];
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
