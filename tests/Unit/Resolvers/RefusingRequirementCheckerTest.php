<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Unit tests for the default requirement checker, which meets nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingRequirementChecker::class)]
final class RefusingRequirementCheckerTest extends TestCase
{
    /**
     * Every part of the requirement is unmet, with no instant, even for a
     * subject in a session.
     *
     * @return void
     */
    public function testFindsEveryPartUnmet(): void
    {
        $user        = new \stdClass;
        $requirement = new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null, 'assurance_level' => null], 'aal2');
        $result      = (new RefusingRequirementChecker)->check($requirement, new Subject($user, $user, session: 'session-1'));

        self::assertFalse($result->isMet);
        self::assertSame(['multifactor', 'phishing_resistant', 'assurance_level'], $result->unmet);
        self::assertNull($result->metUntil);
    }

    /**
     * It reads the request alone, so it is marked `ScopeInvariant` and a query
     * scope reads it once for a query.
     *
     * @return void
     */
    public function testItIsMarkedScopeInvariant(): void
    {
        self::assertContains(ScopeInvariant::class, \class_implements(RefusingRequirementChecker::class));
    }
}
