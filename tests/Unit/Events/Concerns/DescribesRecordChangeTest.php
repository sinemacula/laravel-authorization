<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Concerns;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the audit accessors the role, permission and policy record
 * events and the role permission events share.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(DescribesRecordChange::class)]
final class DescribesRecordChangeTest extends TestCase
{
    /**
     * The change holds where the record's owning tenant is, in no one
     * application, and names no grantee.
     *
     * @return void
     */
    public function testHoldsInTheOwningTenantAndNamesNoGrantee(): void
    {
        $tenant = new Reference('team', '7');
        $event  = new RoleUpdated(Operation::begin(), new Reference('role', '3'), 'editor', 'web', $tenant, ['before' => ['rank' => 1], 'after' => ['rank' => 2]]);

        self::assertSame($tenant, $event->tenant());
        self::assertNull($event->application());
        self::assertSame([], $event->grantees());
        self::assertSame(['role' => 'role:3', 'name' => 'editor', 'guard' => 'web', 'changes.before.rank' => 1, 'changes.after.rank' => 2], $event->auditProperties());
    }

    /**
     * A record the platform owns holds in no tenant.
     *
     * @return void
     */
    public function testHoldsOnThePlatformForAPlatformRecord(): void
    {
        $event = new PolicyCreated(Operation::begin(), new Reference('policy', '9'), 'sharing', null, new DocumentDigest(1, 'abc'), false);

        self::assertNull($event->tenant());
        self::assertSame(['policy' => 'policy:9', 'name' => 'sharing', 'document.version' => 1, 'document.digest' => 'abc', 'is_system' => false], $event->auditProperties());
    }
}
