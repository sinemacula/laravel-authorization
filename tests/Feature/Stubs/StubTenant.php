<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * Minimal Eloquent model representing a tenant entity for
 * multi-tenant scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
class StubTenant extends Model
{
    /**
     * Disable auto-incrementing — stubs use explicit IDs.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * Primary key column.
     *
     * @var string
     */
    protected $primaryKey = 'id';

    /**
     * Primary key type.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Mass-assignable attributes.
     *
     * @var list<string>
     */
    protected $fillable = ['id', 'name'];

    /**
     * Backing table.
     *
     * @var string|null
     */
    protected $table = 'stub_tenants';
}
