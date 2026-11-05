<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Feature tests for replacing the system-protection refusal on a subclass of
 * the shipped `Policy` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Policy::class)]
final class SystemRefusalPolicyTest extends SystemRefusalTestCase
{
    /**
     * Create a `Policy` subclass whose refusal throws a `DomainException`.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModelWithOwnRefusal(): Model
    {
        return new class extends Policy {
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
