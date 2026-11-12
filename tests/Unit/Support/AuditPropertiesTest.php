<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Support\AuditProperties;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the flat, serialisable details a change event reports to an
 * audit mapper.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditProperties::class)]
final class AuditPropertiesTest extends TestCase
{
    /**
     * Every property but the operation, the grantee, the grantees, the tenant
     * and the scope's tenant and application is reported, in order, keyed in
     * snake case: a reference as `type:id`, a date in UTC, a backed enum as its
     * value, a list as a list, and a map or a value object under dotted keys.
     *
     * @return void
     */
    public function testFlattensEveryDetailButWhatTheOtherAccessorsCarry(): void
    {
        $operation = Operation::begin(new Reference('admin', '1'));
        $event     = new readonly class ($operation, new Reference('user', '42'), new Reference('team', '7'), new \DateTimeImmutable('2026-01-02T03:04:05+02:00')) {
            /**
             * Create the fixture, a property of each kind an event carries.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
             * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
             * @param  \DateTimeImmutable  $expiresAt
             * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
             * @param  string  $roleName
             * @param  int  $rank
             * @param  float  $weight
             * @param  bool  $isSystem
             * @param  string|null  $guard
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
             * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $permissions
             * @param  list<scalar>  $labels
             * @param  list<string>  $none
             * @param  array{before: array<string, scalar|null>, after: array<string, scalar|null>}  $changes
             * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
             * @param  \SineMacula\Laravel\Authorization\Support\DocumentDigest  $document
             * @param  \SineMacula\Laravel\Authorization\Support\DocumentDigest|null  $previousDocument
             */
            public function __construct(

                /** The call, left out. */
                public Operation $operation,

                /** The grantee, left out. */
                public Reference $grantee,

                /** The tenant, left out. */
                public ?Reference $tenant,

                /** A date, reported in UTC. */
                public \DateTimeImmutable $expiresAt,

                /** The grantees, left out. */
                public array $grantees = [new Reference('user', '43')],

                /** A string. */
                public string $roleName = 'editor',

                /** An integer. */
                public int $rank = 2,

                /** A float. */
                public float $weight = 1.5,

                /** A boolean. */
                public bool $isSystem = true,

                /** A null. */
                public ?string $guard = null,

                /** A backed enum, reported as its value. */
                public DecisionEffect $effect = DecisionEffect::ALLOW,

                /** A list of references, reported as `type:id` strings. */
                public array $permissions = [new Reference('permission', '5'), new Reference('permission', '6')],

                /** A list of scalars, kept as it is. */
                public array $labels = ['a', 1, false],

                /** An empty list. */
                public array $none = [],

                /** A map, flattened under dotted keys. */
                public array $changes = ['before' => ['name' => 'draft', 'parent_id' => '3'], 'after' => ['name' => 'final', 'parent_id' => null]],

                /** A scope, of which only the reach is reported. */
                public GrantScope $scope = new GrantScope(new Reference('team', '7'), 'admin', false),

                /** A document digest, flattened under dotted keys. */
                public DocumentDigest $document = new DocumentDigest(2, 'def'),

                /** An absent document digest, reported as null. */
                public ?DocumentDigest $previousDocument = null,
            ) {}
        };

        self::assertSame([
            'expires_at'               => '2026-01-02T01:04:05+00:00',
            'role_name'                => 'editor',
            'rank'                     => 2,
            'weight'                   => 1.5,
            'is_system'                => true,
            'guard'                    => null,
            'effect'                   => 'allow',
            'permissions'              => ['permission:5', 'permission:6'],
            'labels'                   => ['a', 1, false],
            'none'                     => [],
            'changes.before.name'      => 'draft',
            'changes.before.parent_id' => '3',
            'changes.after.name'       => 'final',
            'changes.after.parent_id'  => null,
            'scope.include_subtree'    => false,
            'document.version'         => 2,
            'document.digest'          => 'def',
            'previous_document'        => null,
        ], AuditProperties::of($event));
    }

    /**
     * An object that is not one of the package's value objects, a model or a
     * closure among them, is refused rather than reported.
     *
     * @return void
     */
    public function testRefusesAnObjectThatIsNotAPlainValue(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An event detail is not a plain value: stdClass.');

        AuditProperties::of(new readonly class (new \stdClass) {
            /**
             * Create the fixture.
             *
             * @param  object  $model
             */
            public function __construct(

                /** A model or any other object that is not a plain value. */
                public object $model,
            ) {}
        });
    }

    /**
     * A list holding anything but plain values is refused too.
     *
     * @return void
     */
    public function testRefusesAListHoldingAClosure(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An event detail is not a plain value: Closure.');

        AuditProperties::of(new readonly class ([static fn (): bool => true]) {
            /**
             * Create the fixture.
             *
             * @param  list<\Closure(): bool>  $callbacks
             */
            public function __construct(

                /** A list holding a closure. */
                public array $callbacks,
            ) {}
        });
    }
}
