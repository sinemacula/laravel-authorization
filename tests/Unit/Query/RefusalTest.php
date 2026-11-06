<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;

/**
 * Unit tests for one reason a query scope is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Refusal::class)]
final class RefusalTest extends TestCase
{
    /**
     * A refusal about a statement names its policy, by name and key, and the
     * statement, as its reference reads, with the key given.
     *
     * @return void
     */
    public function testARefusalAboutAStatementNamesItsPolicyAndItself(): void
    {
        $statement = new StatementReference('editors', 2, '17', 'Edit');
        $refusal   = Refusal::ofStatement(RefusalReason::RESOURCE_NAMESPACE, $statement, 'resource.status');

        self::assertSame(RefusalReason::RESOURCE_NAMESPACE, $refusal->reason);
        self::assertSame('editors[17]', $refusal->policy);
        self::assertSame('editors[17]#2 sid="Edit"', $refusal->statement);
        self::assertSame('resource.status', $refusal->key);
        self::assertNull($refusal->detail);
        self::assertSame('resource_namespace (statement editors[17]#2 sid="Edit", key resource.status)', $refusal->describe());
        self::assertSame('code#0', Refusal::ofStatement(RefusalReason::INVALID_STATEMENT, new StatementReference('code', 0))->statement);
        self::assertSame('code', Refusal::ofStatement(RefusalReason::INVALID_STATEMENT, new StatementReference('code', 0))->policy);
    }

    /**
     * A refusal describes its reason alone when it names nothing, and names its
     * policy when it names no statement, then its detail.
     *
     * @return void
     */
    public function testARefusalDescribesWhatItNames(): void
    {
        self::assertSame('tenant_tree', (new Refusal(RefusalReason::TENANT_TREE))->describe());
        self::assertSame('record_attachment (statement shared[4])', (new Refusal(RefusalReason::RECORD_ATTACHMENT, 'shared[4]'))->describe());
        self::assertSame('scope_removed (detail call it first)', (new Refusal(RefusalReason::SCOPE_REMOVED, null, null, null, 'call it first'))->describe());
    }
}
