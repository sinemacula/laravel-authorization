<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * `Policy` subclass that hands every base query builder it creates to the
 * `QueryRecorder`.
 *
 * Lets the tests inspect the queries a resolver runs on the policies' table,
 * such as which connection it reads them from and how many pages it reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryRecordingPolicy extends Policy
{
    /** @var string|null Backing table, the policies' own. */
    protected $table = 'policies';

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
