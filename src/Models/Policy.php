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

/**
 * Eloquent model for policy rows.
 *
 * The `document` column persists the full statement body as JSON.
 * Reads round-trip the column through the evaluation policy's
 * `fromArray()` factory; a failing round-trip raises an invalid
 * policy document exception rather than leaving the consumer with a
 * partial object.
 *
 * @property string $id
 * @property string $name
 * @property string|null $description
 * @property array<string, mixed> $document
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
    ];

    /**
     * The attribute casts.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'document' => 'array',
    ];

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
     * Register the row-lifecycle listeners that translate
     * Eloquent's native `created` / `updated` / `deleted` events
     * into the package's typed CRUD events.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::created(static function (self $policy): void {
            Event::dispatch(new PolicyCreated($policy));
        });

        static::updated(static function (self $policy): void {
            Event::dispatch(new PolicyUpdated($policy, $policy->getChanges()));
        });

        static::deleted(static function (self $policy): void {
            Event::dispatch(new PolicyDeleted($policy));
        });
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
