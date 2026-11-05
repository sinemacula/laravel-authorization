<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Foundation\Auth\User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;

/**
 * Unit tests for `InvalidGrantTargetException`, the programming error raised
 * when a grant is handed something that is not a saved model of its kind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidGrantTargetException::class)]
final class InvalidGrantTargetExceptionTest extends TestCase
{
    /**
     * Refused targets with the message each produces.
     *
     * @return iterable<string, array{string, \Closure(): mixed, string}>
     */
    public static function targets(): iterable
    {
        yield 'a model of another kind' => [
            'permission',
            static fn (): mixed => self::savedUser(),
            'A permission grant takes a saved permission model or name, not ' . User::class . '.',
        ];
        yield 'an unsaved model' => ['role', static fn (): mixed => new User, 'A role grant takes a saved role model or name, not an unsaved ' . User::class . '.'];
        yield 'a name for a policy' => ['policy', static fn (): mixed => 'audit', 'A policy grant takes a saved policy model, not string.'];
        yield 'an integer' => ['role', static fn (): mixed => 42, 'A role grant takes a saved role model or name, not int.'];
        yield 'another object' => ['role', static fn (): mixed => new \stdClass, 'A role grant takes a saved role model or name, not stdClass.'];
    }

    /**
     * The message names the kind, what it takes and what it was given, and the
     * kind is exposed.
     *
     * @param  string  $kind
     * @param  \Closure(): mixed  $target
     * @param  string  $message
     * @return void
     */
    #[DataProvider('targets')]
    public function testDescribesTheRefusedTarget(string $kind, \Closure $target, string $message): void
    {
        $exception = new InvalidGrantTargetException($kind, $target());

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame($message, $exception->getMessage());
        self::assertSame($kind, $exception->getKind());
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
