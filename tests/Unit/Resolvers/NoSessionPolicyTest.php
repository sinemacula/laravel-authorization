<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Unit tests for the default session policy source, which carries no cap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoSessionPolicy::class)]
final class NoSessionPolicyTest extends TestCase
{
    /**
     * No credential carries a cap, even a subject's in a session.
     *
     * @return void
     */
    public function testNoCredentialCarriesACap(): void
    {
        $user = new \stdClass;

        self::assertNull((new NoSessionPolicy)->scopesFor(new Subject($user, $user, session: 'session-1')));
    }
}
