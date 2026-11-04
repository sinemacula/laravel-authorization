<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Eloquent identity used by database-backed benchmarks.
 *
 * Mirrors the shape of the test-suite `StubIdentity`, on a table of its own.
 * Kept with the test fixtures, like every other model the package does not
 * ship.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class BenchmarkIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool */
    public $incrementing = false;

    /** @var string */
    protected $primaryKey = 'id';

    /** @var string */
    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = ['id', 'name'];

    /** @var string|null */
    protected $table = 'bench_identities';
}
