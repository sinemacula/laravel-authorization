<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Database\KeyAsText;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * The configured definition models an access review names its targets by: their
 * morph types under the application's morph map, and the kind of grant each
 * type is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Definitions
{
    /**
     * Return the morph type of the configured model of the kind of grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @return string
     */
    public static function morph(GrantTarget $target): string
    {
        return self::model($target)->getMorphClass();
    }

    /**
     * Return the kind of grant whose configured model has the morph type, or
     * null for a type that is none of theirs.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
     */
    public static function kindOf(string $type): ?GrantTarget
    {
        foreach (GrantTarget::cases() as $target) {
            if (self::morph($target) === $type) {
                return $target;
            }
        }

        return null;
    }

    /**
     * Return the table of the configured model of the kind of grant, and the
     * name of its key.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @return array{0: string, 1: string}
     */
    public static function tableOf(GrantTarget $target): array
    {
        $model = self::model($target);

        return [$model->getTable(), $model->getKeyName()];
    }

    /**
     * Determine whether the id could key a definition: the package's tables key
     * every role, permission and policy, and every grant of one, by a UUID, so
     * an id that is none names no definition on any database (PostgreSQL would
     * otherwise refuse to compare it with a `uuid` column).
     *
     * @param  string  $id
     * @return bool
     */
    public static function isKey(string $id): bool
    {
        return Str::isUuid($id);
    }

    /**
     * Return the expression that reads the definition key column of the query's
     * table as text, so it compares with a grantee key column on the query's
     * driver: PostgreSQL casts its `uuid`, any other database stores the key as
     * text already.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @return string
     */
    public static function keyAsText(Builder $query, string $column): string
    {
        return (new KeyAsText($column))->getValue($query->getGrammar());
    }

    /**
     * Return the table of the role permission edges, as `authorization.tables`
     * names it.
     *
     * @return string
     */
    public static function edges(): string
    {
        /** @var string */
        return config('authorization.tables.role_permissions', 'role_permissions');
    }

    /**
     * Return a new instance of the configured model of the kind of grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function model(GrantTarget $target): Model
    {
        [$key, $default] = match ($target) {
            GrantTarget::ROLE       => ['role', Role::class],
            GrantTarget::PERMISSION => ['permission', Permission::class],
            GrantTarget::POLICY     => ['policy', Policy::class],
        };

        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = config('authorization.models.' . $key, $default);

        return new $class;
    }
}
