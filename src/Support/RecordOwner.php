<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;

/**
 * The rules every role, permission and policy row keeps about the tenant that
 * owns it: both tenant columns or neither, and an owner fixed once the row is
 * created (D16), since every grant of the row holds in the scope its owner
 * fixes.
 *
 * Shared by the role, permission and policy observers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordOwner
{
    /**
     * Refuse a row with one tenant column and not the other, and a saved row
     * whose owner would change.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  string  $kind
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     */
    public static function assertValid(Model $record, string $kind): void
    {
        $type = $record->getAttribute('tenant_type');
        $id   = $record->getAttribute('tenant_id');

        if (($type === null) !== ($id === null)) {
            throw new InvalidTenantColumnsException(modelKind: $kind, missingColumn: $type === null ? 'tenant_type' : 'tenant_id');
        }

        if ($record->exists && $record->isDirty(['tenant_type', 'tenant_id'])) {
            /** @var string $name */
            $name = $record->getAttribute('name');

            throw new OwnerChangedException($kind, $name);
        }
    }
}
