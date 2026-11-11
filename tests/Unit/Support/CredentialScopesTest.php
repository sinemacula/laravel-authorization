<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;

/**
 * Unit tests for `CredentialScopes`, what a subject's credential carries: no
 * cap, or the scopes given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialScopes::class)]
final class CredentialScopesTest extends TestCase
{
    /**
     * A credential with no cap is not capped and names no scopes.
     *
     * @return void
     */
    public function testAnUncappedCredentialCarriesNoCap(): void
    {
        $scopes = CredentialScopes::uncapped();

        self::assertFalse($scopes->isCapped());
        self::assertNull($scopes->scopes());
    }

    /**
     * A credential carrying scopes keeps them in order, and one carrying an
     * empty list is capped by it, apart from one with no cap.
     *
     * @return void
     */
    public function testACredentialKeepsTheScopesItCarries(): void
    {
        $scopes = CredentialScopes::of(['posts:read', 'posts:*']);
        $none   = CredentialScopes::of([]);

        self::assertTrue($scopes->isCapped());
        self::assertSame(['posts:read', 'posts:*'], $scopes->scopes());
        self::assertTrue($none->isCapped());
        self::assertSame([], $none->scopes());
    }

    /**
     * Scopes that are not a list of strings that are not empty are refused: a
     * map, a list with an entry that is not a string, and one with an empty
     * string.
     *
     * @return void
     */
    public function testScopesThatAreNotAListOfNamesAreRefused(): void
    {
        $invalid = [
            'a map'         => [1 => 'posts:read'],
            'a keyed map'   => ['read' => 'posts:read'],
            'a number'      => ['posts:read', 42],
            'an empty name' => ['posts:read', ''],
            'a null entry'  => [null],
        ];

        foreach ($invalid as $case => $scopes) {
            try {
                CredentialScopes::of($scopes); // @phpstan-ignore argument.type (each is refused at run time)

                self::fail('The scopes are refused: ' . $case . '.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The scopes of a credential must be a list of strings that are not empty.', $exception->getMessage(), $case);
            }
        }
    }
}
