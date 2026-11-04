<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use Tests\TestCase;

/**
 * Shared checks for the string casts on a shipped model.
 *
 * A driver may hand back a scalar column as an integer or a float; the fillable
 * string columns read back as strings whatever the driver returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class StringCastsTestCase extends TestCase
{
    /**
     * A stored non-string value in a fillable string column reads back as a
     * string.
     *
     * @return void
     */
    public function testStringColumnsReadBackAsStrings(): void
    {
        foreach (static::stringColumns() as $attribute) {
            $model = static::newModel();

            $model->setRawAttributes([$attribute => 123]);

            static::assertSame('123', $model->getAttribute($attribute), $attribute);
        }
    }

    /**
     * A null stored in a fillable string column stays null.
     *
     * @return void
     */
    public function testNullStringColumnsStayNull(): void
    {
        foreach (static::stringColumns() as $attribute) {
            $model = static::newModel();

            $model->setRawAttributes([$attribute => null]);

            static::assertNull($model->getAttribute($attribute), $attribute);
        }
    }

    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    abstract protected static function newModel(): Model;

    /**
     * Return the model's fillable string columns.
     *
     * @return list<string>
     */
    abstract protected static function stringColumns(): array;
}
