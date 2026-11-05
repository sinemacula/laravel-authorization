<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Support\ResourceIdentifier;

/**
 * Unit tests for `ResourceIdentifier`, which turns the value a check is about
 * into the resource identifier the evaluator matches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourceIdentifier::class)]
final class ResourceIdentifierTest extends TestCase
{
    /**
     * No value is no resource, and a string is the resource as given.
     *
     * @return void
     */
    public function testNullIsNoResourceAndAStringIsItself(): void
    {
        self::assertNull(ResourceIdentifier::of(null));
        self::assertSame('post:42', ResourceIdentifier::of('post:42'));
        self::assertSame('', ResourceIdentifier::of(''));
    }

    /**
     * A saved model is `morphClass:key`, and an unsaved one, or one whose key
     * is empty or not a scalar, cannot be identified.
     *
     * @return void
     */
    public function testAModelIsItsMorphClassAndKey(): void
    {
        $model = self::model(42);

        self::assertSame($model->getMorphClass() . ':42', ResourceIdentifier::of($model));
        self::assertSame($model->getMorphClass() . ':0', ResourceIdentifier::of(self::model(0)));
        self::assertFalse(ResourceIdentifier::of(self::model(null)));
        self::assertFalse(ResourceIdentifier::of(self::model('')));
        self::assertFalse(ResourceIdentifier::of(self::model(['a'])));
    }

    /**
     * The resource contract wins over a model's own identifier, saved or not.
     *
     * @return void
     */
    public function testTheResourceContractWinsOverTheModel(): void
    {
        $resource = new class extends Model implements AuthorizableResource {
            /**
             * @return string
             */
            #[\Override]
            public function toResourceIdentifier(): string
            {
                return 'document:7';
            }
        };

        self::assertSame('document:7', ResourceIdentifier::of($resource));
    }

    /**
     * An object that converts to a string is that string.
     *
     * @return void
     */
    public function testAStringableObjectIsItsString(): void
    {
        $value = new class {
            /**
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'report:9';
            }
        };

        self::assertSame('report:9', ResourceIdentifier::of($value));
    }

    /**
     * A number, a list or a plain object cannot be identified.
     *
     * @return void
     */
    public function testOtherValuesCannotBeIdentified(): void
    {
        self::assertFalse(ResourceIdentifier::of(42));
        self::assertFalse(ResourceIdentifier::of(['post:42']));
        self::assertFalse(ResourceIdentifier::of(new \stdClass));
        self::assertFalse(ResourceIdentifier::of(true));
    }

    /**
     * Build a model with the given key.
     *
     * @param  mixed  $key
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function model(mixed $key): Model
    {
        $model = new class extends Model {
            /** @var bool The key is set by hand. */
            public $incrementing = false;
        };

        $model->setRawAttributes(['id' => $key]);

        return $model;
    }
}
