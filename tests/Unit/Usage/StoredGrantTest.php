<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Pivot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for the stored grant a grant route starts from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoredGrant::class)]
final class StoredGrantTest extends TestCase
{
    /**
     * A stored grant is read from its row's columns as stored, its creation
     * read as a UTC wall-clock time, and round-trips through its plain values.
     *
     * @return void
     */
    public function testAStoredGrantIsReadFromItsColumnsAndRoundTrips(): void
    {
        $grant = StoredGrant::of(GrantTarget::POLICY, 'p', new Reference('user', 'u'), [
            'tenant_type' => 'tenant',
            'tenant_id'   => 7,
            'application' => null,
            'created_at'  => '2026-11-09 10:00:00',
        ]);

        self::assertSame([
            'grant_source'      => 'policy',
            'grant_id'          => 'p',
            'authorizable_type' => 'user',
            'authorizable_id'   => 'u',
            'tenant_type'       => 'tenant',
            'tenant_id'         => '7',
            'application'       => null,
            'grant_created_at'  => 1778320800 + 184 * 86400,
        ], $grant->toArray());

        self::assertEquals($grant, StoredGrant::fromArray($grant->toArray()));
        self::assertNull(StoredGrant::of(GrantTarget::ROLE, 'r', new Reference('user', 'u'), ['tenant_type' => []])->tenantType);
        self::assertNull(StoredGrant::of(GrantTarget::ROLE, 'r', new Reference('user', 'u'), [])->createdAt);
    }

    /**
     * A stored grant read through a related model is keyed by the model and
     * read from its pivot's columns; a model with no key is keyed by none.
     *
     * @return void
     */
    public function testAStoredGrantIsReadThroughAPivot(): void
    {
        $related = new class extends Model {};
        $pivot   = (new Pivot)->setRawAttributes(['tenant_type' => 'tenant', 'tenant_id' => 7, 'application' => 'web', 'created_at' => null]);
        $grantee = new Reference('user', 'u');

        $related->setRawAttributes(['id' => 42])->setRelation('pivot', $pivot);

        $grant = StoredGrant::throughPivot(GrantTarget::PERMISSION, $related, $grantee);

        self::assertEquals(new StoredGrant(GrantTarget::PERMISSION, '42', $grantee, 'tenant', '7', 'web', null), $grant);

        $related->setRawAttributes([]);

        self::assertSame('', StoredGrant::throughPivot(GrantTarget::PERMISSION, $related, $grantee)->grantId);
    }

    /**
     * Return values that do not have a stored grant's shape.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function malformed(): iterable
    {
        $valid = (new StoredGrant(GrantTarget::ROLE, 'r', new Reference('user', 'u'), 'tenant', 't', 'web', 5))->toArray();

        yield 'not an array' => ['grant'];
        yield 'an unknown kind' => [[...$valid, 'grant_source' => 'group']];
        yield 'a kind that is no string' => [[...$valid, 'grant_source' => 1]];
        yield 'no key' => [[...$valid, 'grant_id' => null]];
        yield 'no grantee type' => [[...$valid, 'authorizable_type' => 5]];
        yield 'no grantee key' => [\array_diff_key($valid, ['authorizable_id' => true])];
        yield 'a tenant that is no string' => [[...$valid, 'tenant_type' => 5]];
        yield 'a tenant key that is no string' => [[...$valid, 'tenant_id' => false]];
        yield 'an application that is no string' => [[...$valid, 'application' => []]];
        yield 'a creation that is no timestamp' => [[...$valid, 'grant_created_at' => '5']];
    }

    /**
     * Values that do not have a stored grant's shape are refused.
     *
     * @param  mixed  $values
     * @return void
     */
    #[DataProvider('malformed')]
    public function testValuesOfAnotherShapeAreRefused(mixed $values): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored grant is not the shape grant usage tracking keeps.');

        StoredGrant::fromArray($values);
    }
}
