<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;

/**
 * Unit tests for the provenance of a decision: who it was about, who previewed
 * it, and where it was made, as references alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionProvenance::class)]
final class DecisionProvenanceTest extends TestCase
{
    /**
     * A provenance holds what it is given, and none of it by default.
     *
     * @return void
     */
    public function testHoldsWhatItIsGiven(): void
    {
        $subject   = new Reference('user', '1');
        $identity  = new Reference('identity', '2');
        $previewer = new Reference('user', '3');
        $tenant    = new Reference('tenant', '4');

        $provenance = new DecisionProvenance($subject, $identity, $previewer, $tenant, 'admin');

        self::assertSame($subject, $provenance->subject);
        self::assertSame($identity, $provenance->identity);
        self::assertSame($previewer, $provenance->previewer);
        self::assertSame($tenant, $provenance->tenant);
        self::assertSame('admin', $provenance->application);
        self::assertEquals(new DecisionProvenance(null, null, null, null, null), new DecisionProvenance);
    }

    /**
     * The provenance of a decision about a subject names its principal, its
     * identity, its tenant and its application by reference, and no previewer
     * unless one is given.
     *
     * @return void
     */
    public function testNamesTheSubjectByReference(): void
    {
        $principal = self::identity(StubIdentity::class, 'user-1');
        $identity  = self::identity(StubSecondIdentity::class, 'person-1');
        $tenant    = (new StubTenant)->forceFill(['id' => 'tenant-1']);
        $subject   = new Subject($principal, $identity, $tenant, 'admin', 'web', 'session-1');

        $provenance = DecisionProvenance::of($subject);

        self::assertEquals(new Reference($principal->getMorphClass(), 'user-1'), $provenance->subject);
        self::assertEquals(new Reference($identity->getMorphClass(), 'person-1'), $provenance->identity);
        self::assertEquals(new Reference($tenant->getMorphClass(), 'tenant-1'), $provenance->tenant);
        self::assertSame('admin', $provenance->application);
        self::assertNull($provenance->previewer);
        self::assertFalse($provenance->isPreview());

        $previewer = new Reference('user', 'admin-1');
        $preview   = DecisionProvenance::of($subject, $previewer);

        self::assertSame($previewer, $preview->previewer);
        self::assertTrue($preview->isPreview());
        self::assertEquals($provenance->subject, $preview->subject);
    }

    /**
     * A decision about no subject, as a guest's, names no principal, identity,
     * tenant or application.
     *
     * @return void
     */
    public function testNamesNothingForNoSubject(): void
    {
        self::assertEquals(new DecisionProvenance, DecisionProvenance::of(null));
        self::assertEquals(new DecisionProvenance(previewer: new Reference('user', 'admin-1')), DecisionProvenance::of(null, new Reference('user', 'admin-1')));
    }

    /**
     * A tenant given as a reference is named as it is, and a subject with no
     * identity and no tenant names neither.
     *
     * @return void
     */
    public function testNamesATenantGivenAsAReference(): void
    {
        $principal  = self::identity(StubIdentity::class, '7');
        $provenance = DecisionProvenance::of(new Subject($principal, null, new Reference('tenant', 't1')));

        self::assertEquals(new Reference('tenant', 't1'), $provenance->tenant);
        self::assertEquals(new Reference($principal->getMorphClass(), '7'), $provenance->subject);
        self::assertNull($provenance->identity);
        self::assertNull($provenance->application);
        self::assertNull(DecisionProvenance::of(new Subject($principal))->tenant);
    }

    /**
     * A record that is no model or tenant, or a model with no key, is named by
     * no reference, so nothing that is not a saved record is ever named.
     *
     * @return void
     */
    public function testNamesNoRecordWithoutAKey(): void
    {
        $unsaved    = new StubIdentity;
        $provenance = DecisionProvenance::of(new Subject($unsaved, new \stdClass, self::identity(StubIdentity::class, '')));

        self::assertNull($provenance->subject);
        self::assertNull($provenance->identity);
        self::assertNull($provenance->tenant);
    }

    /**
     * Return a model of the class with the key given, unsaved.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  class-string<TModel>  $class
     * @param  string  $key
     * @return TModel
     */
    private static function identity(string $class, string $key): object
    {
        return (new $class)->forceFill(['id' => $key]);
    }
}
