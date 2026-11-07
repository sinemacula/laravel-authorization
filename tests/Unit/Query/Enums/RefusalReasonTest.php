<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;

/**
 * Unit tests for the reasons a query scope is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusalReason::class)]
final class RefusalReasonTest extends TestCase
{
    /**
     * Every reason is a distinct code of lower-case letters and `_`, its case's
     * name in lower case.
     *
     * @return void
     */
    public function testEveryReasonIsItsCaseNameInLowerCase(): void
    {
        $values = \array_map(static fn (RefusalReason $reason): string => $reason->value, RefusalReason::cases());

        foreach (RefusalReason::cases() as $reason) {
            self::assertMatchesRegularExpression('/\A[a-z_]+\z/', $reason->value);
            self::assertSame(\strtolower($reason->name), $reason->value);
        }

        self::assertSame($values, \array_values(\array_unique($values)));
        self::assertSame(RefusalReason::RESOURCE_PATTERN, RefusalReason::from('resource_pattern'));
    }

    /**
     * The reasons the tenancy, attachments and model-level scope raise are
     * there, and those no longer raised, the flat tree's and platform
     * admission's, are gone.
     *
     * @return void
     */
    public function testTheTenancyAndAttachmentReasonsAreDeclared(): void
    {
        $values = \array_map(static fn (RefusalReason $reason): string => $reason->value, RefusalReason::cases());

        foreach (['column_collation', 'subtree_connection', 'attachment_connection', 'attachment_collation', 'too_many_scopes', 'too_many_attachments', 'reentrant'] as $value) {
            self::assertContains($value, $values);
        }

        foreach (['tenant_tree', 'platform_admission', 'record_attachment'] as $value) {
            self::assertNotContains($value, $values);
        }
    }
}
