<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\ContributingAuthenticationContext;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\TestCase;

/**
 * Feature tests for `PolicyValidator`, which decides whether a policy document
 * may be written: its structure, its limits, the context keys its conditions
 * and references read, and the catalogue coverage of its action patterns.
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
                'conditions' => ['eq' => ['input.tenant' => '${subject.tenant.id}'], 'ip_in' => ['request.ip' => '10.0.0.0/8']],
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
     * An allow's principals are accepted on write when they are selectors; a
     * deny naming principals, or a selector that is not a subject reference or
     * a role by its key, is refused.
     *
     * @return void
     */
    public function testChecksThePrincipalsOnWrite(): void
    {
        self::assertSame([], self::validator()->errors(self::document([['effect' => 'allow', 'actions' => ['a'], 'principals' => ['user:1', 'role:9']]])));
        self::assertSame(
            ['Policy statement principals name whom an allow applies to; a deny takes none, and applies to everyone.'],
            self::validator()->errors(self::document([['effect' => 'deny', 'actions' => ['a'], 'principals' => ['user:1']]])),
        );
        self::assertSame(
            ['Policy statement principal \'admins\' must be a subject reference <type>:<id> or a role role:<role id>.'],
            self::validator()->errors(self::document([['effect' => 'allow', 'actions' => ['a'], 'principals' => ['admins']]])),
        );
        self::assertSame(
            ['Policy statement principals must be a non-empty list of selectors.'],
            self::validator()->errors(self::document([['effect' => 'allow', 'actions' => ['a'], 'principals' => []]])),
        );
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
     * A condition on a declared key with an operator its type suits, an
     * `_if_exists` form of one, or `null`, is accepted, and so is a `${…}`
     * reference to a declared key, the subject's and resource's built-ins
     * included.
     *
     * @return void
     */
    public function testAcceptsDeclaredKeysTestedWithOperatorsTheirTypesSuit(): void
    {
        $validator = $this->declaringKeys(['input' => ['post.status' => 'string', 'post.words' => 'number', 'groups' => 'list', 'owner' => 'string', 'draft' => 'bool']]);

        self::assertSame([], $validator->errors(self::document([[
            'effect'     => 'allow',
            'actions'    => ['a'],
            'resources'  => ['post:${input.owner}', 'user:${subject.id}', '${resource.type}:*'],
            'conditions' => [
                'eq'              => ['input.post.status' => '${input.owner}', 'authentication.guard' => 'web', 'input.draft' => true],
                'gte'             => ['input.post.words' => 100],
                'ip_in_if_exists' => ['request.ip' => '10.0.0.0/8'],
                'starts_with'     => ['request.route' => 'posts.', 'authentication.user_type' => '${subject.type}'],
                'before'          => ['environment.time' => '2030-01-01T00:00:00Z'],
                'null'            => ['environment.time' => false, 'input.groups' => false, 'request.ip' => false],
                'any_value_in'    => ['input.groups' => ['editors']],
                'bool'            => ['input.draft' => true],
                'in'              => ['request.method' => ['GET', 'HEAD'], 'authentication.user_id' => ['${subject.id}']],
            ],
        ]])));
    }

    /**
     * Provide condition keys no catalogue declares: flat, a namespace alone, a
     * path below a declared key, one outside the key syntax, and one too long.
     *
     * @return iterable<string, array{string}>
     */
    public static function undeclaredKeys(): iterable
    {
        yield 'a flat key' => ['tenant'];
        yield 'a namespace alone' => ['request'];
        yield 'a path below a declared key' => ['request.ip.v4'];
        yield 'an undeclared input key' => ['input.post.status'];
        yield 'the removed context namespace' => ['context.tenant'];
        yield 'a leading digit' => ['1tenant'];
        yield 'an empty segment' => ['request..ip'];
        yield 'a space' => ['request ip'];
        yield 'an interpolation' => ['${request.ip}'];
        yield 'a key that is too long' => ['input.' . \str_repeat('k', 129)];
    }

    /**
     * A condition key the catalogue does not declare is refused, once for its
     * statement however many operators test it.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('undeclaredKeys')]
    public function testRefusesAConditionKeyNotDeclared(string $key): void
    {
        $document = self::document([
            ['effect' => 'allow', 'actions' => ['a']],
            ['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['request.method' => 'GET', $key => 'x'], 'neq' => [$key => 'y']]],
        ]);

        self::assertSame(
            ["Policy statement #1 condition key '{$key}' is not a declared context key; " . PolicyValidator::DECLARE_KEYS],
            $this->declaringKeys([])->errors($document),
        );
    }

    /**
     * A condition key the catalogue does not declare is refused when only an
     * earlier operator of the statement tests it, so the keys of every operator
     * are checked, not only the last one's.
     *
     * @return void
     */
    public function testRefusesAConditionKeyTestedOnlyByAnEarlierOperator(): void
    {
        $document = self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['tenant' => 'x'], 'neq' => ['request.method' => 'GET']]]]);

        self::assertSame(
            ['Policy statement #0 condition key \'tenant\' is not a declared context key; ' . PolicyValidator::DECLARE_KEYS],
            $this->declaringKeys([])->errors($document),
        );
    }

    /**
     * A condition on a key declared untestable is refused, whatever its
     * operator, while a `${…}` reference may still read it.
     *
     * @return void
     */
    public function testRefusesAConditionOnAnUntestableKey(): void
    {
        $validator = $this->declaringKeys([]);

        $this->keyCatalogue()->declare('mfa.assurance', ContextKeyType::STRING, false);

        self::assertSame(
            ['Policy statement #0 condition key \'mfa.assurance\' may not be tested by a condition.'],
            $validator->errors(self::document([
                ['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['mfa.assurance' => 'high'], 'null' => ['mfa.assurance' => false]]],
            ])),
        );
        self::assertSame([], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['request.route' => '${mfa.assurance}']]]])));
    }

    /**
     * Provide operators that do not suit a declared key's type, with the key,
     * the key's type and the operators that do suit it.
     *
     * @return iterable<string, array{0: string, 1: string, 2: mixed, 3: string, 4: string}>
     */
    public static function unsuitedOperators(): iterable
    {
        $string = 'eq, neq, in, not_in, starts_with, ends_with, like, null';
        $ip     = 'eq, neq, in, not_in, ip_in, ip_not_in, null';
        $time   = 'before, after, between, null';

        yield 'gt on an ip' => ['gt', 'request.ip', 1, 'ip', $ip];
        yield 'like on an ip' => ['like', 'request.ip', '10.*', 'ip', $ip];
        yield 'ip_in on a string' => ['ip_in', 'request.method', '10.0.0.0/8', 'string', $string];
        yield 'an _if_exists form on a string' => ['ip_in_if_exists', 'request.route', '10.0.0.0/8', 'string', $string];
        yield 'eq on a time' => ['eq', 'environment.time', '2030-01-01T00:00:00Z', 'time', $time];
        yield 'gt on a string' => ['gt', 'authentication.user_id', 1, 'string', $string];
        yield 'before on a number' => ['before', 'input.words', '2030-01-01', 'number', 'eq, neq, in, not_in, gt, gte, lt, lte, null'];
        yield 'eq on a list' => ['eq', 'input.groups', 'editors', 'list', 'any_value_in, all_values_in, null'];
        yield 'like on a bool' => ['like', 'input.draft', 'tr*', 'bool', 'eq, neq, bool, null'];
        yield 'any_value_in on a string' => ['any_value_in', 'request.method', ['GET'], 'string', $string];
    }

    /**
     * A condition testing a declared key with an operator its type does not
     * suit is refused, naming the operators that do.
     *
     * @param  string  $operator
     * @param  string  $key
     * @param  mixed  $operand
     * @param  string  $type
     * @param  string  $operators
     * @return void
     */
    #[DataProvider('unsuitedOperators')]
    public function testRefusesAnOperatorThatDoesNotSuitTheKeysType(string $operator, string $key, mixed $operand, string $type, string $operators): void
    {
        $validator = $this->declaringKeys(['input' => ['words' => 'number', 'groups' => 'list', 'draft' => 'bool']]);

        self::assertSame(
            ["Policy statement #0 condition operator '{$operator}' does not suit the {$type} key '{$key}'; use one of {$operators}, or their _if_exists forms."],
            $validator->errors(self::document([['effect' => 'deny', 'actions' => ['a'], 'conditions' => [$operator => [$key => $operand]]]])),
        );
    }

    /**
     * A `${…}` reference to a key the catalogue does not declare is refused,
     * once for its statement, in an operand or a resource pattern, and so is
     * the removed `${context.…}` namespace; the subject's and resource's
     * built-ins are declared.
     *
     * @return void
     */
    public function testRefusesAReferenceToAKeyNotDeclared(): void
    {
        $document = self::document([
            ['effect' => 'allow', 'actions' => ['a'], 'resources' => ['post:${input.post}', '${resource.type}:${subject.id}']],
            ['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['request.route' => '${context.route}', 'request.method' => '${input.post}-${context.route}']]],
        ]);

        self::assertSame([
            'Policy statement #0 reference \'${input.post}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #1 reference \'${context.route}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #1 reference \'${input.post}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
        ], $this->declaringKeys([])->errors($document));
        self::assertSame([], $this->declaringKeys(['input' => ['post' => 'string'], 'context' => ['route' => 'string']])->errors($document));
    }

    /**
     * A `${…}` reference in a `not_resources` pattern is checked like one in
     * `resources`: refused when it names no declared key, accepted when it
     * names a declared key, a built-in of the subject or resource included.
     *
     * @return void
     */
    public function testRefusesAReferenceInANotResourcesPatternToAKeyNotDeclared(): void
    {
        $validator = $this->declaringKeys(['input' => ['post' => 'string']]);
        $statement = static fn (string $pattern): array => self::document([['effect' => 'deny', 'actions' => ['a'], 'not_resources' => [$pattern]]]);

        self::assertSame(
            ['Policy statement #0 reference \'${input.undeclared}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS],
            $validator->errors($statement('post:${input.undeclared}')),
        );
        self::assertSame([], $validator->errors($statement('post:${subject.id}')));
        self::assertSame([], $validator->errors($statement('post:${input.post}')));
    }

    /**
     * A `${principal.…}` reference is refused as undeclared, as the namespace
     * is gone, and so is a subject or resource attribute no provider declares,
     * in a reference or a condition; one a provider declares is accepted.
     *
     * @return void
     */
    public function testRefusesThePrincipalAndUndeclaredAttributes(): void
    {
        $document = self::document([[
            'effect'     => 'allow',
            'actions'    => ['a'],
            'resources'  => ['post:${principal.id}', 'post:${resource.owner.id}'],
            'conditions' => ['eq' => ['resource.status' => 'draft', 'subject.department' => '${subject.team}']],
        ]]);

        self::assertSame([
            'Policy statement #0 condition key \'resource.status\' is not a declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #0 condition key \'subject.department\' is not a declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #0 reference \'${principal.id}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #0 reference \'${resource.owner.id}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
            'Policy statement #0 reference \'${subject.team}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS,
        ], $this->declaringKeys([])->errors($document));

        $this->app?->instance(ContextKeyCatalogue::class, new DeclaredContextKeyCatalogue([], [
            'resource' => ['App\PostAttributes' => ['status' => 'string', 'owner.id' => 'string']],
            'subject'  => ['App\UserAttributes' => ['department' => 'string', 'team' => 'string']],
        ]));

        self::assertSame(
            ['Policy statement #0 reference \'${principal.id}\' names no declared context key; ' . PolicyValidator::DECLARE_KEYS],
            self::validator()->errors($document),
        );
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
        yield 'ends_with with a nul byte and a reference' => ['ends_with', "\${input.suffix}\0"];
        yield 'ip_in with a nul byte' => ['ip_in', "10.0.0.0\0/8"];
        yield 'ip_not_in with a nul byte' => ['ip_not_in', "10.0.0.1\0"];
        yield 'ip_in with a zone id' => ['ip_in', 'fe80::1%en0'];
        yield 'ip_in with a leading zero' => ['ip_in', '010.0.0.0/8'];
        yield 'before with a nul byte' => ['before', "2026-01-01\0"];
        yield 'after with a nul byte and a reference' => ['after', "\${input.deadline}\0"];
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
        $document = self::document([['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['input.x' => $operand]]]]);

        self::assertSame(["Policy document cannot be encoded as JSON: {$reason}."], self::validator()->errors($document));
    }

    /**
     * A structural fault stops the check: only it and the limits the document
     * breaks are given, and the context key and catalogue checks do not run.
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
     * With no permissions configured, or a catalogue that declares no action at
     * all, a document whose patterns need any action but the package's own is
     * refused with the one reason that nothing is declared, an `actions` and a
     * `not_actions` pattern alike, one naming the package's own beside it
     * included.
     *
     * @return void
     */
    public function testRefusesADocumentNeedingAnyOtherActionWhenNothingIsDeclared(): void
    {
        $reason = 'No permissions are declared to check the policy\'s actions against; declare them in permission_enums or permission_providers.';

        foreach ([$this->declaring([], []), $this->bound(new EmptyActionCatalogue)] as $validator) {
            self::assertSame([$reason], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['posts:create']], ['effect' => 'deny', 'actions' => ['*']]])));
            self::assertSame([$reason], $validator->errors(self::document([['effect' => 'allow', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE, 'posts:create']]])));
            self::assertSame([$reason], $validator->errors(self::document([['effect' => 'deny', 'not_actions' => ['posts:*']]])));
        }
    }

    /**
     * With no permissions configured, or a catalogue that declares no action at
     * all, a document naming only the package's own permissions, by name or by
     * a pattern that covers one, may still be written, and so may one with no
     * statement.
     *
     * @return void
     */
    public function testAcceptsThePackagesOwnPermissionsWhenNothingIsDeclared(): void
    {
        foreach ([$this->declaring([], []), $this->bound(new EmptyActionCatalogue)] as $validator) {
            self::assertSame([], $validator->errors(self::document([['effect' => 'allow', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE, 'authorization:*']]])));
            $wide = [['effect' => 'deny', 'actions' => ['*']], ['effect' => 'allow', 'not_actions' => ['authorization:guardrail.*']]];

            self::assertSame([], $validator->errors(self::document($wide)));
            self::assertSame([], $validator->errors(self::document([])));
        }
    }

    /**
     * With the application's permissions declared, a pattern covering only the
     * package's own permissions is accepted beside them, though the catalogue
     * never holds the package's own.
     *
     * @return void
     */
    public function testAcceptsThePackagesOwnPermissionsBesideTheApplications(): void
    {
        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([], $validator->errors(self::document([['effect' => 'allow', 'actions' => ['posts:create', PackagePermissions::GUARDRAIL_MANAGE, 'authorization:*']]])));
        self::assertSame(
            ['Policy statement #0 actions pattern \'authorization:roles:*\' matches no declared permission.'],
            $validator->errors(self::document([['effect' => 'allow', 'actions' => ['authorization:roles:*']]])),
        );
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
     * Every limit, context key and catalogue reason is given together.
     *
     * @return void
     */
    public function testGivesEveryReasonTogether(): void
    {
        $this->config()->set('authorization.policies.limits.pattern_length', 12);

        $this->declaringKeys([]);

        $validator = $this->declaring([CataloguePermission::class], []);

        self::assertSame([
            'Policy statement #0 has 1 patterns or operands longer than the 12 characters allowed.',
            'Policy statement #0 condition key \'1st\' is not a declared context key; ' . PolicyValidator::DECLARE_KEYS,
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
     * An authentication requirement is accepted without any key declared: the
     * catalogue is never asked about its key.
     *
     * @return void
     */
    public function testAcceptsARequirementWithoutDeclaringItsKey(): void
    {
        $document = self::document([[
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => []]]],
        ]]);

        self::assertSame([], $this->declaringKeys([])->errors($document));
    }

    /**
     * A malformed requirement is refused as the statement is.
     *
     * @return void
     */
    public function testRefusesAMalformedRequirement(): void
    {
        $document = self::document([[
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['hardware_key' => []]]],
        ]]);

        self::assertSame(['Policy statement authentication requirement names an unknown part \'hardware_key\'.'], self::validator()->errors($document));
    }

    /**
     * Provide documents testing or referencing an assurance key, with the
     * reason each is refused.
     *
     * @return iterable<string, array{list<array<string, mixed>>, string}>
     */
    public static function assuranceKeyProvider(): iterable
    {
        $point = 'is an assurance key, which no condition may test or reference; '
            . 'state the requirement with the authentication_requirement operator on the key \'authentication\' instead.';

        yield 'a condition on authentication.amr' => [
            [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['any_value_in' => ['authentication.amr' => ['otp']]]]],
            "Policy statement #0 condition key 'authentication.amr' {$point}",
        ];
        yield 'a suffixed condition on authentication.assurance_level' => [
            [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq_if_exists' => ['authentication.assurance_level' => 'aal2']]]],
            "Policy statement #0 condition key 'authentication.assurance_level' {$point}",
        ];
        yield 'a condition on a contributed namespace' => [
            [['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['gt' => ['mfa.seconds_since_step_up' => 900]]]],
            "Policy statement #0 condition key 'mfa.seconds_since_step_up' {$point}",
        ];
        yield 'a reference in an operand' => [
            [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.time' => '${authentication.auth_time}']]]],
            "Policy statement #0 reference '\${authentication.auth_time}' names 'authentication.auth_time', which {$point}",
        ];
        yield 'a reference in a resource pattern' => [
            [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['post:${mfa.multifactor}']]],
            "Policy statement #0 reference '\${mfa.multifactor}' names 'mfa.multifactor', which {$point}",
        ];
    }

    /**
     * A condition on an assurance key, or a reference to one, is refused and
     * pointed at the requirement operator, even when the catalogue would permit
     * it.
     *
     * @param  list<array<string, mixed>>  $statements
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('assuranceKeyProvider')]
    public function testRefusesAssuranceKeys(array $statements, string $reason): void
    {
        $this->app?->instance(AuthenticationContext::class, new ContributingAuthenticationContext(['mfa']));

        self::assertSame([$reason], self::validator()->errors(self::document($statements)));
    }

    /**
     * Without a contributing authentication context only `authentication` holds
     * assurance keys, so a key of the same name elsewhere is judged by the
     * catalogue alone.
     *
     * @return void
     */
    public function testOnlyAuthenticationHoldsAssuranceKeysByDefault(): void
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue $actions */
        $actions   = $this->app?->make(ActionCatalogue::class);
        $validator = new PolicyValidator($actions, $this->keyCatalogue());
        $document  = self::document([['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['gt' => ['mfa.seconds_since_step_up' => 900]]]]);

        self::assertSame([], $validator->errors($document));
        self::assertSame([], self::validator()->errors($document));
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
     * Return a validator asking the action catalogue, and the bound context key
     * catalogue.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue  $catalogue
     * @return \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator
     */
    private function bound(ActionCatalogue $catalogue): PolicyValidator
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue $keys */
        $keys = $this->app?->make(ContextKeyCatalogue::class);

        return new PolicyValidator($catalogue, $keys);
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
     * Declare the context keys, bind the declared context key catalogue in
     * place of the test suite's permissive one, and return the validator.
     *
     * @param  array<string, array<string, string>>  $keys
     * @return \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator
     */
    private function declaringKeys(array $keys): PolicyValidator
    {
        $this->app?->instance(ContextKeyCatalogue::class, new DeclaredContextKeyCatalogue($keys));

        return self::validator();
    }

    /**
     * Return the bound context key catalogue.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue
     */
    private function keyCatalogue(): ContextKeyCatalogue
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue */
        return $this->app?->make(ContextKeyCatalogue::class);
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
