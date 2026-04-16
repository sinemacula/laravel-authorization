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
use SineMacula\Laravel\Authorization\Traits\HasSystemProtection;

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
    use HasSystemProtection, HasUuids;

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

        // @codeCoverageIgnoreStart — defensive: the preceding `EvaluationPolicy::fromArray` round-trip would itself have failed on a non-JSON-encodable payload (it calls `json_encode` during trace normalisation), so reaching this branch requires a resource type or a circular reference smuggled past the factory validator.
        if ($encoded === false) {
            throw new InvalidPolicyDocumentException(policyName: $this->resolveName(), reason: 'policy document is not JSON-encodable.');
        }
        // @codeCoverageIgnoreEnd

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
     * into the package's typed CRUD events. System-protection
     * hooks (`deleting`, `updating` guard, `saved` bypass reset)
     * are registered by `HasSystemProtection::bootHasSystemProtection()`.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::updating(static function (self $policy): void {
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
    }

    /**
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For policies, both
     * `name` and `document` changes are protected — the document
     * carries the authorization payload and its mutation is the
     * security-relevant edit on the Policy table (#91).
     *
     * @return list<string>
     */
    protected function systemProtectedFields(): array
    {
        return ['name', 'document'];
    }

    /**
     * Construct the per-model exception raised when a protected
     * mutation on a system policy is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    protected function systemProtectionException(string $operation): \Throwable
    {
        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which policy was targeted" (the canonical persisted
        // name), not "what the attempted rename would produce."
        /** @var string $policyName */
        $policyName = $this->getOriginal('name', $this->getAttribute('name'));

        return new SystemPolicyProtectedException(policyName: $policyName, operation: $operation);
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
}
