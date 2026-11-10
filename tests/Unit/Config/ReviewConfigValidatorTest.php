<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ReviewConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for the boot-time validation of `authorization.reviews`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewConfigValidator::class)]
final class ReviewConfigValidatorTest extends TestCase
{
    /**
     * An empty block, whose limit takes its default, and a whole `limit` of at
     * least 1, written as an int or as the environment gives a whole number,
     * are accepted, and the limit is returned as an int.
     *
     * @return void
     */
    public function testAWholeLimitIsAccepted(): void
    {
        ReviewConfigValidator::validate([]);
        ReviewConfigValidator::validate(['limit' => 1]);
        ReviewConfigValidator::validate(['limit' => 1000]);

        self::assertSame(1, ReviewConfigValidator::limit(1));
        self::assertSame(250, ReviewConfigValidator::limit(250));
        self::assertSame(1000, ReviewConfigValidator::limit('1000'));
        ReviewConfigValidator::validate(['limit' => '1']);
        self::assertSame(['limit'], ReviewConfigValidator::SETTINGS);
        self::assertSame('authorization.reviews', ReviewConfigValidator::KEY);
    }

    /**
     * Return each invalid block, with the key it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function invalidBlocks(): iterable
    {
        $whole = 'expected a whole number of at least 1, got ';

        yield 'not an array' => ['1000', 'authorization.reviews', 'expected an array, got \'1000\' (string).'];
        yield 'null' => [null, 'authorization.reviews', 'expected an array, got \'null\' (null).'];
        yield 'an unknown setting' => [['max_rows' => 4], 'authorization.reviews.max_rows', 'unknown key \'max_rows\'; expected one of limit.'];
        yield 'an unknown setting after one' => [['limit' => 5, 'max_rows' => 4], 'authorization.reviews.max_rows', 'unknown key \'max_rows\'; expected one of limit.'];
        yield 'zero' => [['limit' => 0], 'authorization.reviews.limit', $whole . '0 (int).'];
        yield 'zero as a string' => [['limit' => '0'], 'authorization.reviews.limit', $whole . '\'0\' (string).'];
        yield 'negative' => [['limit' => -1], 'authorization.reviews.limit', $whole . '-1 (int).'];
        yield 'a string not a whole number' => [['limit' => '12abc'], 'authorization.reviews.limit', $whole . '\'12abc\' (string).'];
        yield 'an exponent' => [['limit' => '1e3'], 'authorization.reviews.limit', $whole . '\'1e3\' (string).'];
        yield 'a padded string' => [['limit' => ' 5'], 'authorization.reviews.limit', $whole . '\' 5\' (string).'];
        yield 'an empty string' => [['limit' => ''], 'authorization.reviews.limit', $whole . '\'\' (string).'];
        yield 'a float' => [['limit' => 1.5], 'authorization.reviews.limit', $whole . '1.5 (float).'];
        yield 'a null' => [['limit' => null], 'authorization.reviews.limit', $whole . '\'null\' (null).'];
        yield 'a list' => [['limit' => [1]], 'authorization.reviews.limit', $whole . '\'array\' (array).'];
        yield 'a boolean' => [['limit' => true], 'authorization.reviews.limit', $whole . 'true (bool).'];
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
            ReviewConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("Invalid authorization config at '{$key}': {$reason}", $exception->getMessage());
            self::assertSame($key, $exception->getConfigKey());
        }
    }
}
