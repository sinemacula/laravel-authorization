<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Writes the conditions a row of a tenant-bearing model meets for its tenant:
 * it has none, as the tenant resolver reads it; it has one the resolver can
 * read, at most 191 bytes in each part; it is exactly a tenant, byte for byte,
 * the plain comparison an index can serve first; or it is within a tenant's
 * subtree, as the bound tenant tree selects it.
 *
 * The subtree is the tree's own query (`TenantTree::subtree()`), nested whole,
 * its text image of each tenant compared byte for byte with the text PHP reads
 * from the row's columns, with every value it is bound to inlined as the
 * dialect writes a bound value (`InlinedQuery`); under the flat tree a tenant's
 * subtree is the tenant alone, compared as such. A subtree query run on another
 * connection than the model's cannot be nested, so it is refused
 * (`subtree_connection`); so is one the model's connection would run on a
 * separate read connection (`read_replica`), and one a value of which cannot be
 * inlined exactly (`inline_value`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantMembership
{
    /** @var string The alias the subtree query is nested under. */
    private const string ALIAS = 'authz_subtree';

    /** @var array<string, string> The condition of each subtree written, by tenant. */
    private array $subtrees = [];

    /**
     * Create a new writer of tenant conditions.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $action
     */
    public function __construct(

        /** The model queried, which declares tenant columns. */
        private readonly ResourceShape $shape,

        /** The action the query is scoped to, which refusals name. */
        private readonly string $action,
    ) {}

    /**
     * Return the condition a row meets when it has no tenant the resolver can
     * read: either tenant column null, the resolver reading both before
     * either's null, so each holds what PHP reads as a string, an integer or
     * null.
     *
     * @return string
     */
    public function ofNone(): string
    {
        $shape  = $this->shape;
        $isNull = $shape->typeColumn === null ? "{$shape->idColumn} IS NULL" : "({$shape->typeColumn} IS NULL OR {$shape->idColumn} IS NULL)";

        return Conditions::all([$isNull, ...\array_map($shape->dialect->readable(...), $this->columns())]);
    }

    /**
     * Return the condition a row meets when it has a tenant the resolver can
     * read: neither column null, each read as a string or an integer, at most
     * 191 bytes.
     *
     * @return string
     */
    public function present(): string
    {
        $conditions = [];

        foreach ($this->columns() as $column) {
            $length = 'length(' . $this->shape->dialect->textImage($column) . ') <= ' . Reference::MAX_BYTES;

            \array_push($conditions, "{$column} IS NOT NULL", $this->shape->dialect->readable($column), $length);
        }

        return Conditions::all($conditions);
    }

    /**
     * Return the condition a row meets when its tenant columns hold exactly the
     * tenant's type and key, byte for byte.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    public function equalTo(Reference $tenant): string
    {
        $shape = $this->shape;

        /** @var string $idColumn */
        $idColumn = $shape->idColumn;

        /** @var \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind $idKind */
        $idKind  = $shape->idKind;
        $isFixed = $shape->tenancy->type === $tenant->type ? QueryAuthorizer::EVERY_ROW : QueryAuthorizer::NO_ROW;
        $isType  = $shape->typeColumn    === null ? [$isFixed] : $this->equals($shape->typeColumn, ColumnKind::STRING, $tenant->type);

        return Conditions::all([...$isType, ...$this->equals($idColumn, $idKind, $tenant->id)]);
    }

    /**
     * Return the condition a row meets when its tenant is the tenant or below
     * it, as the bound tree's subtree query selects them.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public function within(Reference $tenant): string
    {
        $tree = TenantChain::tree();

        if ($tree instanceof FlatTenantTree) {
            return $this->equalTo($tenant);
        }

        return $this->subtrees[$tenant->type . "\0" . $tenant->id] ??= $this->subtreeOf($tree->subtree($tenant));
    }

    /**
     * Return the condition a row meets when the subtree query selects its
     * tenant, refusing a query on another connection than the model's, one read
     * on a separate read connection, and one that cannot be inlined.
     *
     * @param  mixed  $subtree
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private function subtreeOf(mixed $subtree): string
    {
        $shape      = $this->shape;
        $query      = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;
        $connection = $query instanceof Builder ? $query->getConnection() : null;

        if (!$query instanceof Builder || !$connection instanceof Connection || $connection->getName() !== $shape->connection?->getName()) {
            throw $this->refusal(RefusalReason::SUBTREE_CONNECTION);
        }

        $isReadOnWrite = InlinedQuery::isReadOnWrite($connection);
        $raw           = $isReadOnWrite ? InlinedQuery::sqlOf($query, $shape->dialect) : null;

        if ($raw === null) {
            throw $this->refusal($isReadOnWrite ? RefusalReason::INLINE_VALUE : RefusalReason::READ_REPLICA);
        }

        $grammar = $connection->getQueryGrammar();
        $dialect = $shape->dialect;
        $type    = $shape->typeColumn === null ? $dialect->bytes((string) $shape->tenancy->type) : $dialect->textImage($shape->typeColumn);

        $isType = $dialect->textImage($grammar->wrap(self::ALIAS . '.tenant_type')) . ' = ' . $type;
        $isId   = $dialect->textImage($grammar->wrap(self::ALIAS . '.tenant_id')) . ' = ' . $dialect->textImage((string) $shape->idColumn);

        return 'EXISTS (SELECT 1 FROM (' . $raw . ') AS ' . $grammar->wrap(self::ALIAS) . " WHERE {$isType} AND {$isId})";
    }

    /**
     * Return the refusal of the bound tree's subtree query for the reason.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason  $reason
     * @return \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private function refusal(RefusalReason $reason): QueryScopeRefusedException
    {
        return QueryScopeRefusedException::of($this->action, $this->shape->type, new Refusal($reason, null, null, TenantChain::tree()::class));
    }

    /**
     * Return the conditions a row whose column holds exactly the value meets:
     * the bare column's comparison, which an index can serve and which every
     * such row meets, then the exact byte comparison.
     *
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  string  $value
     * @return list<string>
     */
    private function equals(string $column, ColumnKind $kind, string $value): array
    {
        return [$this->shape->dialect->equalsIndexed($column, $kind, $value), $this->shape->dialect->equalsBytes($column, $value)];
    }

    /**
     * Return the model's tenant columns, qualified and wrapped.
     *
     * @return list<string>
     */
    private function columns(): array
    {
        return \array_values(\array_filter([$this->shape->typeColumn, $this->shape->idColumn], static fn (?string $column): bool => $column !== null));
    }
}
