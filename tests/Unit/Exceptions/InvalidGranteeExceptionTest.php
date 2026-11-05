<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Foundation\Auth\User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Support\GranteeReference;

/**
 * Unit tests for `InvalidGranteeException`, the programming error raised when a
 * grant is handed a grantee it cannot write a grant for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidGranteeException::class)]
final class InvalidGranteeExceptionTest extends TestCase
{
    /** @var string The start every refusal's message shares. */
    private const string PREFIX = 'A grant takes a saved grantee with a type and a key, not ';

    /**
     * Refused grantees with the message each produces.
     *
     * @return iterable<string, array{\Closure(): object, string}>
     */
    public static function grantees(): iterable
    {
        yield 'an unsaved model' => [static fn (): object => new User, self::PREFIX . 'an unsaved ' . User::class . '.'];
        yield 'a saved model' => [static fn (): object => self::savedUser(), self::PREFIX . 'an incomplete ' . User::class . '.'];
        yield 'a reference' => [static fn (): object => new GranteeReference('', ''), self::PREFIX . 'an incomplete ' . GranteeReference::class . '.'];
    }

    /**
     * The message says what a grant takes and describes the grantee it was
     * given.
     *
     * @param  \Closure(): object  $grantee
     * @param  string  $message
     * @return void
     */
    #[DataProvider('grantees')]
    public function testDescribesTheRefusedGrantee(\Closure $grantee, string $message): void
    {
        $exception = new InvalidGranteeException($grantee());

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame($message, $exception->getMessage());
    }

    /**
     * Return a model marked as saved, without a database.
     *
     * @return \Illuminate\Foundation\Auth\User
     */
    private static function savedUser(): User
    {
        $user         = new User;
        $user->exists = true;

        return $user;
    }
}
