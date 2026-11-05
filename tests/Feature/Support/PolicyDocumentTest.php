<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\TestCase;

/**
 * Feature tests for reading a stored policy document: decoding it, naming it
 * after the stored policy and hydrating it for evaluation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyDocument::class)]
final class PolicyDocumentTest extends TestCase
{
    /**
     * A stored policy hydrates under its own name, whatever its document says.
     *
     * @return void
     */
    public function testHydratesUnderTheStoredName(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => ['name' => 'writers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $hydrated = PolicyDocument::hydrate($policy);

        self::assertSame('readers', $hydrated->name);
        self::assertSame(['posts:read'], $hydrated->statements[0]->actions);
    }

    /**
     * A stored document that is not a valid policy is refused under the
     * policy's name, keeping the cause.
     *
     * @return void
     */
    public function testAnInvalidStoredDocumentIsRefused(): void
    {
        $policy = new Policy;
        $policy->setRawAttributes(['name' => 'broken', 'document' => '{"statements":[{"effect":"sometimes"}]}']);

        try {
            PolicyDocument::hydrate($policy);
            self::fail('An invalid document was hydrated.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('broken', $exception->getPolicyName());
            self::assertInstanceOf(\Throwable::class, $exception->getPrevious());
        }
    }

    /**
     * A document decodes from an array or a JSON object or array string; any
     * other value is refused under the name given.
     *
     * @return void
     */
    public function testDecodesAnArrayOrAJsonString(): void
    {
        self::assertSame(['version' => 1], PolicyDocument::decode(['version' => 1], 'p'));
        self::assertSame(['version' => 1], PolicyDocument::decode('{"version":1}', 'p'));
        self::assertCount(2, PolicyDocument::decode('[1,2]', 'p'));

        foreach (['', '"text"', null, 42] as $value) {
            try {
                PolicyDocument::decode($value, 'named');
                self::fail('A value that is not a document was decoded.');
            } catch (InvalidPolicyDocumentException $exception) {
                self::assertSame('named', $exception->getPolicyName());
                self::assertStringContainsString('policy document must be a JSON object or array.', $exception->getMessage());
            }
        }
    }

    /**
     * The document takes the policy's name when it names none, or always when
     * overriding; a policy without a name leaves the document as it is.
     *
     * @return void
     */
    public function testNamesTheDocumentAfterThePolicy(): void
    {
        self::assertSame(['name' => 'stored'], PolicyDocument::named([], 'stored'));
        self::assertSame(['name' => 'stored'], PolicyDocument::named(['name' => ''], 'stored'));
        self::assertSame(['name' => 'stored'], PolicyDocument::named(['name' => 42], 'stored'));
        self::assertSame(['name' => 'own'], PolicyDocument::named(['name' => 'own'], 'stored'));
        self::assertSame(['name' => 'stored'], PolicyDocument::named(['name' => 'own'], 'stored', true));
        self::assertSame(['name' => 'own'], PolicyDocument::named(['name' => 'own'], '', true));
        self::assertSame([], PolicyDocument::named([], null));
    }

    /**
     * A policy is reported under its name, or the placeholder without one.
     *
     * @return void
     */
    public function testReportsAPolicyUnderItsNameOrThePlaceholder(): void
    {
        self::assertSame('readers', PolicyDocument::nameOf('readers'));
        self::assertSame('[unnamed]', PolicyDocument::nameOf(''));
        self::assertSame('[unnamed]', PolicyDocument::nameOf(null));
    }
}
