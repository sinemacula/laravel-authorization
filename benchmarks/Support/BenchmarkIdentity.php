<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Eloquent identity used by database-backed benchmarks.
 *
 * Mirrors the shape of the test-suite `StubIdentity` but lives in the
 * `Benchmarks` namespace so the bench runner never touches the test autoload
 * tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Fillable('id', 'name')]
#[Table(name: 'bench_identities', keyType: 'string', incrementing: false)]
class BenchmarkIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;
}
