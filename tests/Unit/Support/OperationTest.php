<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `Operation`, one call that changes the package's records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operation::class)]
final class OperationTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An operation begun with no actor is trusted: it has a new UUID, no actor,
     * no identity, no impersonator, no actions, and the current time in UTC.
     *
     * @return void
     */
    public function testBeginsTrustedWithANewIdAndTheTimeInUtc(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-07-01 14:00:00', 'Europe/Paris'));

        $operation = Operation::begin();

        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $operation->id);
        self::assertNull($operation->actor);
        self::assertTrue($operation->isTrusted);
        self::assertNull($operation->identity);
        self::assertNull($operation->impersonator);
        self::assertSame([], $operation->actions);
        self::assertSame('2026-07-01T12:00:00+00:00', $operation->at->format(\DATE_ATOM));
        self::assertSame('UTC', $operation->at->getTimezone()->getName());
    }

    /**
     * Each operation has an id of its own.
     *
     * @return void
     */
    public function testEachOperationHasItsOwnId(): void
    {
        self::assertNotSame(Operation::begin()->id, Operation::begin()->id);
    }

    /**
     * A reference a trusted command names is the actor of a trusted operation,
     * for the record alone.
     *
     * @return void
     */
    public function testAReferenceAttributesATrustedOperation(): void
    {
        $reference = new Reference('user', '7');
        $operation = Operation::begin($reference, [PackagePermissions::PERMISSION_CREATE]);

        self::assertSame($reference, $operation->actor);
        self::assertTrue($operation->isTrusted);
        self::assertNull($operation->identity);
        self::assertSame([PackagePermissions::PERMISSION_CREATE], $operation->actions);
    }

    /**
     * An acting context makes the operation delegated: its actor is the acting
     * principal, with the identity behind it and the impersonator, and its
     * actions are listed once each, in the order given.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnActingContextMakesTheOperationDelegated(): void
    {
        $principal = self::saved('42');
        $identity  = self::saved('7');
        $actor     = ActingContext::for(new Subject($principal, $identity))->impersonatedBy(new Reference('support', '3'));
        $operation = Operation::begin($actor, [PackagePermissions::ROLE_GRANT, PackagePermissions::ROLE_REVOKE, PackagePermissions::ROLE_GRANT]);

        self::assertEquals(new Reference('stub', '42'), $operation->actor);
        self::assertEquals(new Reference('stub', '7'), $operation->identity);
        self::assertEquals(new Reference('support', '3'), $operation->impersonator);
        self::assertFalse($operation->isTrusted);
        self::assertSame([PackagePermissions::ROLE_GRANT, PackagePermissions::ROLE_REVOKE], $operation->actions);
    }

    /**
     * Return a model that reads as saved, with the key.
     *
     * @param  string  $key
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function saved(string $key): Model
    {
        $model = new class extends Model {
            /** @var string Primary key type. */
            protected $keyType = 'string';

            /**
             * Return the model's morph type, short whatever path declares it.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'stub';
            }
        };

        $model->forceFill(['id' => $key]);
        $model->exists = true;

        return $model;
    }
}
