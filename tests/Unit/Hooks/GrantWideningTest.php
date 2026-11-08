<?php

declare(strict_types = 1);

namespace Tests\Unit\Hooks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `GrantWidening`, what a grant call proposes that widens an
 * identity's scope, as the grant hook is handed it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantWidening::class)]
final class GrantWideningTest extends TestCase
{
    /**
     * The reasons are those of every grant, each once, in the order the reasons
     * are declared.
     *
     * @return void
     */
    public function testTheReasonsAreEachGrantsOnceInDeclaredOrder(): void
    {
        $identity = new Reference('identities', '1');
        $changes  = [
            self::change([WideningReason::INCOMPLETE_DIRECTORY, WideningReason::NEW_TENANT]),
            self::change([WideningReason::IDENTITY, WideningReason::NEW_TENANT]),
            self::change([]),
        ];

        $widening = new GrantWidening('operation', true, null, null, null, $identity, $identity, $changes, new \DateTimeImmutable);

        self::assertSame([WideningReason::IDENTITY, WideningReason::NEW_TENANT, WideningReason::INCOMPLETE_DIRECTORY], $widening->reasons);
        self::assertSame($changes, $widening->changes);
        self::assertSame([], (new GrantWidening('operation', true, null, null, null, $identity, $identity, [], new \DateTimeImmutable))->reasons);
    }

    /**
     * The widening of an operation carries its id, mode and actor references.
     *
     * @return void
     */
    public function testTheWideningOfAnOperationCarriesItsActor(): void
    {
        $operation = new Operation('id-1', new Reference('principals', 'a'), new \DateTimeImmutable, false, new Reference('identities', 'a'), new Reference('identities', 'i'));
        $identity  = new Reference('identities', '1');
        $grantee   = new Reference('principals', '2');
        $at        = new \DateTimeImmutable('@100');

        $widening = GrantWidening::of($operation, $identity, $grantee, [self::change([WideningReason::PLATFORM])], $at);

        self::assertSame('id-1', $widening->operationId);
        self::assertFalse($widening->isTrusted);
        self::assertSame(['a', 'a', 'i'], [$widening->actor?->id, $widening->actorIdentity?->id, $widening->impersonator?->id]);
        self::assertSame(['principals', 'identities', 'identities'], [$widening->actor?->type, $widening->actorIdentity?->type, $widening->impersonator?->type]);
        self::assertSame([$identity, $grantee, $at], [$widening->identity, $widening->grantee, $widening->observedAt]);
        self::assertSame([WideningReason::PLATFORM], $widening->reasons);
    }

    /**
     * A widening is to the identity only when the grantee is the identity, by
     * type and key.
     *
     * @return void
     */
    public function testAWideningIsToTheIdentityOnlyWhenTheGranteeIsIt(): void
    {
        $identity = new Reference('identities', '1');
        $at       = new \DateTimeImmutable;

        self::assertTrue((new GrantWidening('o', true, null, null, null, $identity, new Reference('identities', '1'), [], $at))->isToIdentity());
        self::assertFalse((new GrantWidening('o', true, null, null, null, $identity, new Reference('principals', '1'), [], $at))->isToIdentity());
        self::assertFalse((new GrantWidening('o', true, null, null, null, $identity, new Reference('identities', '2'), [], $at))->isToIdentity());
    }

    /**
     * Return a proposed grant with the reasons.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Enums\WideningReason>  $reasons
     * @return \SineMacula\Laravel\Authorization\Hooks\ProposedGrant
     */
    private static function change(array $reasons): ProposedGrant
    {
        return new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), null, null, true, null, $reasons);
    }
}
