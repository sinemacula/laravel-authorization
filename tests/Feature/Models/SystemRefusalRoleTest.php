<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Feature tests for replacing the system-protection refusal on a subclass of
 * the shipped `Role` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
final class SystemRefusalRoleTest extends SystemRefusalTestCase
{
    /**
     * Create a `Role` subclass whose refusal throws a `DomainException`.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModelWithOwnRefusal(): Model
    {
        return new class extends Role {
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
