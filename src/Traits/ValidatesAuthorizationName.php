<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;

/**
 * Shared name-format validator for role and permission models.
 *
 * Role and permission names feed `fnmatch` during evaluation — the
 * holder-matches-asker walk in `HasPermissions::hasPermission()` and the action
 * / resource match in `Statement`. Allowing glob metacharacters (`?`, `[`, `]`,
 * `{`, `}`) or whitespace would let a malformed name match unrelated
 * permissions, so the mutator enforces a tight character class at save time.
 * The typed exception surfaces immediately, before the row reaches the
 * database.
 *
 * Consumers set `$this->authorizationNameKind` (e.g. `'role'`, `'permission'`)
 * to control the label used in the raised exception; that is the only per-model
 * customisation point.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait ValidatesAuthorizationName // @phpstan-ignore trait.unused
{
    /** @var string Pattern permitted in role and permission names. */
    private const string NAME_PATTERN = '/^[A-Za-z0-9_\-:*]+$/';

    /**
     * Validate the `name` attribute before it is persisted.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException
     */
    public function setNameAttribute(mixed $value): void
    {
        if (!is_string($value) || $value === '' || preg_match(self::NAME_PATTERN, $value) !== 1) {
            throw new InvalidAuthorizationNameException($this->getAuthorizationNameKind(), is_string($value) ? $value : '');
        }

        $this->attributes['name'] = $value;
    }

    /**
     * Return the human-readable label used to identify the model in a
     * name-validation error message. Override per model.
     *
     * @return string
     */
    protected function getAuthorizationNameKind(): string
    {
        return 'authorization entity';
    }
}
