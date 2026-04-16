<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\PolicyCreated;
use SineMacula\Laravel\Authorization\Events\PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\PolicyUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;

/**
 * Eloquent model for policy rows.
 *
 * The `document` column persists the full statement body as JSON.
 * Reads round-trip the column through the evaluation policy's
 * `fromArray()` factory; a failing round-trip raises an invalid
 * policy document exception rather than leaving the consumer with a
 * partial object. The `is_system` flag marks platform-shipped
 * policies as delete-protected: deletion or a rename of an
 * `is_system = true` row raises `SystemPolicyProtectedException`
 * unless `forceSystem()` is invoked to unlock the next operation on
 * the instance.
 *
 * @property string $id
 * @property string $name
 * @property string|null $description
 * @property array<string, mixed> $document
 * @property bool $is_system
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Policy extends Model
{
    use HasUuids;

    /** Placeholder name used when exception context has no policy name available. */
    private const string UNNAMED_PLACEHOLDER = '[unnamed]';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'description',
        'document',
        'is_system',
    ];

    /**
     * The attribute casts.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'document'  => 'array',
        'is_system' => 'boolean',
    ];

    /**
     * Per-instance escape-hatch flag. When true, the next delete
     * or rename bypasses the system-policy protection and resets
     * to false on completion. Invoked via `forceSystem()` — never
     * persisted, never inherited across instances.
     *
     * @var bool
     */
    private bool $systemProtectionBypassed = false;

    /**
     * Pre-save attribute snapshot captured on `updating` and
     * consumed by the `updated` listener so `PolicyUpdated`
     * carries a complete before/after diff. Reset after each
     * dispatch so a follow-up save observes a clean slate.
     *
     * @var array<string, mixed>
     */
    private array $beforeChangeSnapshot = [];

    /**
     * Create a new Eloquent model instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        /** @var string $table */
        $table       = config('authorization.tables.policies', 'policies');
        $this->table = $table;
    }

    /**
     * Unlock the next protected mutation (delete or rename) on
     * this instance. Returns `$this` for chaining:
     *
     *     $policy->forceSystem()->delete();
     *
     * The bypass is **per-instance, single-use, and in-memory** —
     * it never persists to the database, never leaks across
     * instances (a `$policy->fresh()` drops it), and resets to
     * false the moment the guard clause consults it.
     *
     * @return static
     */
    public function forceSystem(): static
    {
        $this->systemProtectionBypassed = true;

        return $this;
    }

    /**
     * Set the document attribute, validating it round-trips through
     * the evaluation policy factory.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException
     */
    public function setDocumentAttribute(mixed $value): void
    {
        $document = $this->normaliseDocument($value);
        $document = $this->withName($document);

        try {
            EvaluationPolicy::fromArray($document);
        } catch (\InvalidArgumentException $exception) {
            throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: $exception->getMessage(), previous: $exception);
        }

        $encoded = \json_encode($document);

        if ($encoded === false) {
            throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: 'policy document is not JSON-encodable.');
        }

        $this->attributes['document'] = $encoded;
    }

    /**
     * Hydrate the policy into an evaluation-ready value object.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException
     */
    public function toEvaluationPolicy(): EvaluationPolicy
    {
        $document = $this->normaliseDocument($this->document);
        $document = $this->withName($document);

        try {
            return EvaluationPolicy::fromArray($document);
        } catch (\Throwable $exception) {
            throw new InvalidPolicyDocumentException(policyName: $this->name, reason: $exception->getMessage(), previous: $exception);
        }
    }

    /**
     * Register the row-lifecycle listeners that translate
     * Eloquent's native `created` / `updated` / `deleted` events
     * into the package's typed CRUD events, and enforce the
     * system-policy protection invariant on `deleting` /
     * `updating` before the row reaches the database.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::deleting(static function (self $policy): void {
            $policy->assertSystemProtectionAllows('delete');
        });

        static::updating(static function (self $policy): void {
            if ($policy->wasSystemPolicyRenamed()) {
                $policy->assertSystemProtectionAllows('rename');
            }

            $snapshot = [];

            foreach (\array_keys($policy->getDirty()) as $key) {
                $snapshot[$key] = $policy->getOriginal($key);
            }

            $policy->beforeChangeSnapshot = $snapshot;
        });

        static::created(static function (self $policy): void {
            Event::dispatch(new PolicyCreated($policy));
        });

        static::updated(static function (self $policy): void {
            Event::dispatch(new PolicyUpdated($policy, [
                'before' => $policy->beforeChangeSnapshot,
                'after'  => $policy->getChanges(),
            ]));

            $policy->beforeChangeSnapshot = [];
        });

        static::deleted(static function (self $policy): void {
            Event::dispatch(new PolicyDeleted($policy));
        });

        // Clear the bypass flag after every completed save so it
        // cannot hop across an intervening non-protected mutation
        // (e.g. a description update) and silently unlock the next
        // rename or delete. `saved` fires after `updating` has had
        // a chance to consume the flag for a legitimate rename, so
        // this reset is strictly idempotent on that path.
        static::saved(static function (self $policy): void {
            $policy->systemProtectionBypassed = false;
        });
    }

    /**
     * Coerce a raw document value into an associative array.
     *
     * @param  mixed  $value
     * @return array<string, mixed>
     */
    private function normaliseDocument(mixed $value): array
    {
        if (\is_array($value)) {
            /** @var array<string, mixed> $value */
            return $value;
        }

        if (\is_string($value) && $value !== '') {
            $decoded = \json_decode($value, true);

            if (\is_array($decoded)) {
                /** @var array<string, mixed> $decoded */
                return $decoded;
            }
        }

        throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: 'policy document must be a JSON object or array.');
    }

    /**
     * Resolve the policy name used in exception context.
     *
     * @return string
     */
    private function resolveName(): string
    {
        $name = $this->name ?? ($this->attributes['name'] ?? null);

        return \is_string($name) && $name !== '' ? $name : self::UNNAMED_PLACEHOLDER;
    }

    /**
     * Ensure the document body carries the model's name.
     *
     * @param  array<string, mixed>  $document
     * @return array<string, mixed>
     */
    private function withName(array $document): array
    {
        if (!isset($document['name']) || !\is_string($document['name']) || $document['name'] === '') {
            $name = $this->name ?? ($this->attributes['name'] ?? null);

            if (\is_string($name) && $name !== '') {
                $document['name'] = $name;
            }
        }

        return $document;
    }

    /**
     * Decide whether the supplied mutation is allowed against the
     * current instance. Consumes the bypass flag so a second
     * protected operation on the same instance re-arms the
     * protection.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException
     */
    private function assertSystemProtectionAllows(string $operation): void
    {
        if ((bool) $this->getAttribute('is_system') === false) {
            return;
        }

        if ($this->systemProtectionBypassed) {
            $this->systemProtectionBypassed = false;

            return;
        }

        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which policy was targeted" (the canonical persisted
        // name), not "what the attempted rename would produce."
        /** @var string $policyName */
        $policyName = $this->getOriginal('name', $this->getAttribute('name'));

        throw new SystemPolicyProtectedException(policyName: $policyName, operation: $operation);
    }

    /**
     * Test whether the pending update renames a system policy.
     * Only rename operations go through the protection check;
     * description and document bumps pass unconditionally.
     *
     * @return bool
     */
    private function wasSystemPolicyRenamed(): bool
    {
        if (!(bool) $this->getAttribute('is_system')) {
            return false;
        }

        /** @var array<string, mixed> $dirty */
        $dirty = $this->getDirty();

        return \array_key_exists('name', $dirty);
    }
}
