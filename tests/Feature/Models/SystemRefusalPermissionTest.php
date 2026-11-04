<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Feature tests for replacing the system-protection refusal on a subclass of
 * the shipped `Permission` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Permission::class)]
final class SystemRefusalPermissionTest extends SystemRefusalTestCase
{
    /**
     * Create a `Permission` subclass whose refusal throws a `DomainException`.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModelWithOwnRefusal(): Model
    {
        return new class extends Permission {
            /**
             * Build the refusal as a `DomainException` carrying the operation.
             *
             * @param  string  $operation
             * @return \Throwable
             */
            #[\Override]
            protected function systemProtectionException(string $operation): \Throwable
            {
                return new \DomainException($operation);
            }
        };
    }
}
