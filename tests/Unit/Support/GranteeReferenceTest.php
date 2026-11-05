<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Support\GranteeReference;

/**
 * Unit tests for `GranteeReference`, a grantee named by its morph type and key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GranteeReference::class)]
final class GranteeReferenceTest extends TestCase
{
    /**
     * The reference answers its type and key as a model does, so the resolution
     * cache keys it as the grantee it names.
     *
     * @return void
     */
    public function testAnswersItsTypeAndKeyAsAModelDoes(): void
    {
        $reference = new GranteeReference('user', '42');

        self::assertSame('user', $reference->getMorphClass());
        self::assertSame('42', $reference->getKey());
        self::assertSame('user:42', PrincipalCacheKey::for($reference));
    }
}
