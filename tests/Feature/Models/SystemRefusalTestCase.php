<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Shared checks that a subclass of a shipped model can replace the exception
 * raised when a protected change to a system record is refused.
 *
 * The guard calls the model's `systemProtectionException()` factory, so a
 * subclass that overrides it changes what the refusal throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class SystemRefusalTestCase extends TestCase
{
    /**
     * A refused delete on a system record throws the exception the subclass
     * builds.
     *
     * @return void
     */
    public function testSubclassReplacesRefusal(): void
    {
        $model = static::newModelWithOwnRefusal();

        $model->setRawAttributes([
            'id'        => (string) Str::uuid(),
            'name'      => 'system-record',
            'is_system' => true,
        ], true);

        $model->exists = true;

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('delete');

        $model->delete();
    }

    /**
     * Create an instance of a subclass of the model under test whose refusal
     * throws a `DomainException` carrying the operation.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    abstract protected static function newModelWithOwnRefusal(): Model;
}
