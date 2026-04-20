<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;

/**
 * Minimal Eloquent model representing a tenant entity for multi-tenant scoping
 * tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Fillable('id', 'name')]
#[Table(name: 'stub_tenants', keyType: 'string', incrementing: false)]
class StubTenant extends Model {}
