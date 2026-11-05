<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * `Role` subclass that hands every base query builder it creates to the
 * `QueryRecorder`.
 *
 * Lets the tests inspect the queries the model runs on its own behalf, such as
 * which connection the system-protection guard reads the stored flag from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryRecordingRole extends Role
{
    /**
     * Create a new base query builder and record it.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    #[\Override]
    protected function newBaseQueryBuilder(): Builder
    {
        $query = parent::newBaseQueryBuilder();

        QueryRecorder::record($query);

        return $query;
    }
}
