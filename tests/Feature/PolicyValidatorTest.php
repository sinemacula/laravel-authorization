<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\TestCase;

/**
 * Feature tests for `PolicyValidator`, which decides whether a policy document
 * may be written: its structure, its limits, its condition keys and the
 * catalogue coverage of its action patterns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyValidator::class)]
final class PolicyValidatorTest extends TestCase
{
    /**
     * Reset the configurable provider before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ConfigurablePermissionProvider::$permissions = [];
    }

    /**
     * A valid document has no errors and is accepted.
     *
     * @return void
     */
    public function testAcceptsAValidDocument(): void
    {
        $document = self::document([
            [
                'sid'        => 'Read',
                'effect'     => 'allow',
                'actions'    => ['posts:read'],
                'conditions' => ['eq' => ['tenant' => '${subject.tenant}'], 'ip_in' => ['request.ip' => '10.0.0.0/8']],
            ],
            ['sid' => 'Write', 'effect' => 'deny', 'not_actions' => ['posts:read'], 'not_resources' => ['post:1']],
        ]);

        self::assertSame([], self::validator()->errors($document));

        self::validator()->assertValid($document, 'readers');
    }

    /**
     * A document that is not an array is refused.
     *
     * @return void
     */
    public function testRefusesADocumentThatIsNotAnObject(): void
    {
        self::assertSame(['Policy document must be a JSON object.'], self::validator()->errors('{"statements": []}'));
        self::assertSame(['Policy document must be a JSON object.'], self::validator()->errors(null));
    }

    /**
     * A document that is not a valid policy is refused with the policy's own
     * reason, two statements sharing a sid included.
     *
     * @return void
     */
    public function testRefusesAnInvalidPolicy(): void
    {
        $shared = self::document([['sid' => 'A', 'effect' => 'allow', 'actions' => ['a']], ['sid' => 'A', 'effect' => 'deny', 'actions' => ['b']]]);

        self::assertSame(['Policy document has statements sharing a sid: A.'], self::validator()->errors($shared));
        self::assertSame(['Policy document has unknown keys: rules.'], self::validator()->errors(['name' => 'p', 'rules' => []]));
        self::assertSame(['Policy statement conditions have an unknown operator \'cidr\'.'], self::validator()->errors(self::document([
            ['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['cidr' => ['request.ip' => '10.0.0.0/8']]],
        ])));
    }

    /**
     * A document over the limits is refused for each limit, alongside any
     * reason it is not a valid policy.
     *
     * @return void
     */
    public function testRefusesADocumentOverTheLimits(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        $document = self::document([['effect' => 'allow', 'actions' => ['a']], ['effect' => 'allow', 'actions' => ['b']]]);

        self::assertSame(['Policy document has 2 statements, more than the 1 allowed.'], self::validator()->errors($document));

        $document['statements'][] = ['effect' => 'audit', 'actions' => ['c']];

        self::assertSame([
            'Policy document has 3 statements, more than the 1 allowed.',
            'Invalid policy effect: \'audit\'',
        ], self::validator()->errors($document));
    }

    /**
     * Return condition keys in the key syntax.
     *
     * @return iterable<string, array{string}>
     */
    public static function validKeys(): iterable
    {
        yield 'a name' => ['tenant'];
        yield 'a name with an underscore' => ['_request_ip'];
        yield 'dotted segments' => ['request.ip'];
        yield 'segments with digits and -' => ['subject.attr-1.2_b'];
        yield 'the longest key' => [\str_repeat('k', 128)];
    }

    /**
     * A condition key in the key syntax, of at most 128 characters, is
     * accepted.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('validKeys')]
    public function testAcceptsAConditionKeyInTheKeySyntax(string $key): void
    {
        self::assertSame([], self::validator()->errors(self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => [$key => 'x']]]])));
    }

    /**
     * Return condition keys outside the key syntax.
     *
     * @return iterable<string, array{string}>
     */
    public static function invalidKeys(): iterable
    {
        yield 'a leading digit' => ['1tenant'];
        yield 'a dash in the first name' => ['request-ip'];
        yield 'an empty segment' => ['request..ip'];
        yield 'a trailing dot' => ['request.'];
        yield 'a leading dot' => ['.request'];
        yield 'a space' => ['request ip'];
        yield 'an interpolation' => ['${subject.id}'];
        yield 'a trailing newline' => ["tenant\n"];
        yield 'a key that is too long' => [\str_repeat('k', 129)];
    }

    /**
     * A condition key outside the key syntax, or longer than 128 characters, is
     * refused, once for its statement however many operators test it.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('invalidKeys')]
    public function testRefusesAConditionKeyOutsideTheKeySyntax(string $key): void
    {
        $document = self::document([
            ['effect' => 'allow', 'actions' => ['a']],
            ['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['tenant' => 'x', $key => 'x'], 'neq' => [$key => 'y']]],
        ]);

        self::assertSame([
            "Policy statement #1 condition key '{$key}' must be letters, digits and '_', then any '.'-separated segments that may also hold '-', and at most 128 characters.",
        ], self::validator()->errors($document));
    }

    /**
     * A condition key outside the key syntax is refused when only an earlier
     * operator of the statement tests it, so the keys of every operator are
     * checked, not only the last one's.
     *
     * @return void
     */
    public function testRefusesAConditionKeyTestedOnlyByAnEarlierOperator(): void
    {
        $document = self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['1bad' => 'x'], 'neq' => ['tenant' => 'y']]]]);

        self::assertSame([
            'Policy statement #0 condition key \'1bad\' must be letters, digits and \'_\', then any \'.\'-separated segments that may also hold \'-\', and at most 128 characters.',
        ], self::validator()->errors($document));
    }

    /**
     * Provide operands holding a NUL byte, or an address only some platforms
     * read, with the operator they are written for.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function unreadableOperands(): iterable
    {
        yield 'like with a nul byte' => ['like', "curl\0*"];
        yield 'starts_with with a nul byte' => ['starts_with', "/a\0"];
        yield 'ends_with with a nul byte and a reference' => ['ends_with', "\${context.suffix}\0"];
        yield 'ip_in with a nul byte' => ['ip_in', "10.0.0.0\0/8"];
        yield 'ip_not_in with a nul byte' => ['ip_not_in', "10.0.0.1\0"];
        yield 'ip_in with a zone id' => ['ip_in', 'fe80::1%en0'];
        yield 'ip_in with a leading zero' => ['ip_in', '010.0.0.0/8'];
        yield 'before with a nul byte' => ['before', "2026-01-01\0"];
        yield 'after with a nul byte and a reference' => ['after', "\${context.deadline}\0"];
    }

    /**
     * An operand holding a NUL byte, or an address with a zone id or a leading
     * zero, is refused as an invalid operand, never thrown as a ValueError.
     *
     * @param  string  $operator
     * @param  string  $operand
     * @return void
     */
    #[DataProvider('unreadableOperands')]
    public function testRefusesAnOperandNoPlatformReadsTheSameWay(string $operator, string $operand): void
    {
        $document = self::document([['effect' => 'deny', 'actions' => ['a'], 'conditions' => [$operator => ['k' => $operand]]]]);

        self::assertSame(["Policy statement condition 'k' has an invalid operand for operator '{$operator}'."], self::validator()->errors($document));
    }

    /**
     * A resource pattern holding a NUL byte is refused, since no resource can
     * match it.
     *
     * @return void
     */
    public function testRefusesAResourcePatternHoldingANulByte(): void
    {
        $document = self::document([['effect' => 'allow', 'actions' => ['a'], 'resources' => ["post:\0*"]]]);

        self::assertSame(['Policy statement resource pattern holds a NUL byte.'], self::validator()->errors($document));
    }

    /**
     * Provide documents that cannot be encoded as JSON, with the reason.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function unencodableOperands(): iterable
    {
        yield 'nan' => [\NAN, 'Inf and NaN cannot be JSON encoded'];
        yield 'infinity' => [-\INF, 'Inf and NaN cannot be JSON encoded'];
        yield 'invalid utf-8' => ["\xff", 'Malformed UTF-8 characters, possibly incorrectly encoded'];
    }

    /**
     * A document that cannot be encoded as JSON is refused, so it is never
     * reported valid and then refused only when it is stored.
     *
     * @param  mixed  $operand
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('unencodableOperands')]
    public function testRefusesADocumentThatCannotBeEncoded(mixed $operand, string $reason): void
    {
        $document = self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['x' => $operand]]]]);

        self::assertSame(["Policy document cannot be encoded as JSON: {$reason}."], self::validator()->errors($document));
    }

    /**
     * A structural fault stops the check: only it and the limits the document
     * breaks are given, and the condition-key and catalogue checks do not run.
     *
     * @return void
     */
    public function testAStructuralFaultHidesTheOtherReasons(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([
            'Policy document has 2 statements, more than the 1 allowed.',
            'Policy statement conditions have an unknown operator \'cidr\'.',
        ], $validator->errors(self::document([
            ['effect' => 'allow', 'actions' => ['psts:read'], 'conditions' => ['eq' => ['bad key' => 'x']]],
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['cidr' => ['ip' => '10.0.0.0/8']]],
        ])));
    }

    /**
     * With no permissions declared, every document is refused with the one
     * reason, whatever actions it names.
     *
     * @return void
     */
    public function testRefusesEveryDocumentWhenNoPermissionsAreDeclared(): void
    {
        $validator = $this->declaring([], []);

        $reason = 'No permissions are declared to check the policy\'s actions against; declare them in permission_enums or permission_providers.';

        self::assertSame([$reason], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['posts:create']], ['effect' => 'deny', 'actions' => ['*']]])));
        self::assertSame([$reason], $validator->errors(self::document([])));
    }

    /**
     * An `actions` pattern must cover a permission a declared enum declares.
     *
     * @return void
     */
    public function testChecksTheActionsAgainstADeclaredEnum(): void
    {
        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['posts:create', 'posts.publish', 'posts:*', '*']]])));
        self::assertSame([
            'Policy statement #0 actions pattern \'posts:delete\' matches no declared permission.',
            'Policy statement #1 actions pattern \'comments:*\' matches no declared permission.',
        ], $validator->errors(self::document([
            ['effect' => 'allow', 'actions' => ['posts:create', 'posts:delete']],
            ['effect' => 'deny', 'actions' => ['comments:*']],
        ])));
    }

    /**
     * An `actions` pattern must cover a permission a declared provider
     * declares.
     *
     * @return void
     */
    public function testChecksTheActionsAgainstADeclaredProvider(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'reports:export')];

        $validator = $this->declaring([], [ConfigurablePermissionProvider::class]);

        self::assertSame([], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['reports:export']]])));
        self::assertSame(
            ['Policy statement #0 actions pattern \'posts:create\' matches no declared permission.'],
            $validator->errors(self::document([['effect' => 'allow', 'actions' => ['posts:create']]])),
        );
    }

    /**
     * A `not_actions` pattern must cover a declared permission too, so a
     * mistyped exception never widens the statement to every action.
     *
     * @return void
     */
    public function testChecksTheNotActionsAgainstTheCatalogue(): void
    {
        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([], $validator->errors(self::document([['effect' => 'deny', 'not_actions' => ['posts:create']]])));
        self::assertSame(
            ['Policy statement #0 not_actions pattern \'posts:craete\' matches no declared permission.'],
            $validator->errors(self::document([['effect' => 'deny', 'not_actions' => ['posts:create', 'posts:craete']]])),
        );
    }

    /**
     * Every limit, condition-key and catalogue reason is given together.
     *
     * @return void
     */
    public function testGivesEveryReasonTogether(): void
    {
        $this->config()->set('authorization.policies.limits.pattern_length', 12);

        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([
            'Policy statement #0 has 1 patterns or operands longer than the 12 characters allowed.',
            'Policy statement #0 condition key \'1st\' must be letters, digits and \'_\', then any \'.\'-separated segments that may also hold \'-\', and at most 128 characters.',
            'Policy statement #0 actions pattern \'comments:create\' matches no declared permission.',
        ], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['comments:create'], 'conditions' => ['eq' => ['1st' => 'x']]]])));
    }

    /**
     * An invalid document is refused with every reason, joined by `; ` into one
     * sentence, under the given name.
     *
     * @return void
     */
    public function testAssertValidRefusesWithEveryReason(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        try {
            self::validator()->assertValid(self::document([['effect' => 'allow', 'actions' => ['a']], ['effect' => 'audit', 'actions' => ['b']]]), 'readers');
            self::fail('The document was not refused.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('readers', $exception->getPolicyName());
            self::assertSame(
                'Invalid policy document \'readers\': Policy document has 2 statements, more than the 1 allowed; Invalid policy effect: \'audit\'.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * Reasons are joined into one sentence, each without its own full stop.
     *
     * @return void
     */
    public function testJoinsReasonsIntoOneSentence(): void
    {
        self::assertSame('One.', PolicyValidator::joined(['One.']));
        self::assertSame('One; two; three.', PolicyValidator::joined(['One.', 'two', 'three..']));
    }

    /**
     * Build a document named `p` holding the statements.
     *
     * @param  list<array<string, mixed>>  $statements
     * @return array{name: string, statements: list<array<string, mixed>>}
     */
    private static function document(array $statements): array
    {
        return ['name' => 'p', 'statements' => $statements];
    }

    /**
     * Return the validator the container builds, with the bound catalogue.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator
     */
    private static function validator(): PolicyValidator
    {
        /** @var \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator */
        return app(PolicyValidator::class);
    }

    /**
     * Declare the enums and providers, bind the declared action catalogue in
     * place of the test suite's permissive one, and return the validator.
     *
     * @param  list<class-string>  $enums
     * @param  list<class-string>  $providers
     * @return \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator
     */
    private function declaring(array $enums, array $providers): PolicyValidator
    {
        $this->config()->set('authorization.permission_enums', $enums);
        $this->config()->set('authorization.permission_providers', $providers);

        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));

        return self::validator();
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
