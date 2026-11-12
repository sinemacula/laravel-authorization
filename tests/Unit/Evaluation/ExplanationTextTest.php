<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationText;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the explanation's text renderer: every line it writes, and
 * every name escaped so none can inject markup, control characters or a line of
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ExplanationText::class)]
final class ExplanationTextTest extends TestCase
{
    /**
     * An explained allow renders its verdict, each step with its tests and
     * unresolved references, each grant with its path and scope, the keys found
     * missing and the request.
     *
     * @return void
     */
    public function testAnExplainedAllow(): void
    {
        $user      = new Reference('user', '1');
        $statement = new StatementReference('own', 0, 'key', 'Read', 'posts:7');
        $decision  = Decision::allow(DecisionStage::ALLOW, [$statement], [
            new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, ['input.team' => true, 'input.flag' => false], null, null, [], [
                new ConditionResult('input.team', 'eq', ConditionOutcome::HELD),
                new ConditionResult('input.flag', 'eq', ConditionOutcome::HELD, true, true),
                new ConditionResult('input.other', 'eq', ConditionOutcome::UNRESOLVED, false, false, ['input.a', 'input.b']),
            ], ['input.prefix']),
        ])->withEvidence(new DecisionEvidence([
            new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:*', $user, false, ['editor', 'author'], true, new Reference('team', 'a'), 'web'),
            new GrantProvenance(GrantSource::PERMISSION, 'posts:read', new Reference('person', '2'), true, [], true),
            new GrantProvenance(GrantSource::RESOURCE_POLICY, 'share on posts:*'),
            GrantProvenance::unavailable('coded'),
        ], new ExplanationRequest('posts:read', 'posts:7', new DecisionProvenance($user), self::decidedIn(new Reference('team', 'a'), 'web'))));

        self::assertSame(
            "ALLOW at the allow stage by own[key]#0 sid=\"Read\" on \"posts:7\".\n"
            . "  [guardrail] guardrails: uncapped\n"
            . "  [allow] own[key]#0 sid=\"Read\" on \"posts:7\": matched (input.team held, input.flag failed)\n"
            . "      test input.team eq: held\n"
            . "      test input.flag eq_if_exists: held (key missing)\n"
            . "      test input.other eq: unresolved, unresolved \${input.a}, \${input.b}\n"
            . "      resource pattern unresolved \${input.prefix}\n"
            . "  grant role permission \"posts:*\" to principal user:1 through role \"editor\" < \"author\" in tenant team:a for application \"web\"\n"
            . "  grant permission \"posts:read\" to identity person:2 in platform\n"
            . "  grant resource policy \"share on posts:*\", scope unavailable\n"
            . "  grant unavailable \"coded\": provenance unavailable\n"
            . "  missing input.prefix, input.a, input.b\n"
            . '  request "posts:read" on "posts:7" about user:1 (identity person:2), previewed by user:9; asked in platform, decided in tenant team:a for application "web"',
            ExplanationText::render($decision->explain()),
        );
    }

    /**
     * A denial renders its reason, each requirement by its part names and unmet
     * parts, the caps that refused it, the stages not evaluated, and, without
     * explain mode, that the evidence was not recorded.
     *
     * @return void
     */
    public function testADenialWithoutExplainMode(): void
    {
        $capped = Decision::deny(DecisionReason::BOUNDARY, DecisionStage::BOUNDARY, [], [
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::REFUSED, null, [], 'cap[9]'),
        ]);
        $unmet = Decision::insufficientAuthentication(DecisionStage::IMPLICIT, [new StatementReference('p', 0)], [
            new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]), ['multifactor']),
        ]);

        self::assertSame(
            "DENY (boundary: a permission boundary does not allow it) at the boundary stage by boundary \"cap[9]\".\n"
            . "  [boundary] cap[9]: refused\n"
            . "  not evaluated: session, allow, administration, implicit\n"
            . '  evidence: not recorded (explain mode off)',
            ExplanationText::render($capped->explain()),
        );
        self::assertStringContainsString("\n  requirement multifactor, phishing_resistant: unmet multifactor\n", ExplanationText::render($unmet->explain()));
        self::assertStringNotContainsString('900', ExplanationText::render($unmet->explain()));
    }

    /**
     * A step about no statement and no cap names what its stage weighs, and a
     * request about no saved subject says so.
     *
     * @return void
     */
    public function testWhatAStepIsAbout(): void
    {
        $decision = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::EXEMPT),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD),
            new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED),
        ])->withEvidence(new DecisionEvidence([], new ExplanationRequest('posts:read', null, new DecisionProvenance, new DecisionProvenance)));

        self::assertSame(
            "DENY (no_match: no statement or permission names it) at the implicit stage.\n"
            . "  [guardrail] guardrails: exempt\n"
            . "  [boundary] boundaries: uncapped\n"
            . "  [session] session caps: uncapped\n"
            . "  [allow] permission: not_held\n"
            . "  [administration] administration constraints: satisfied\n"
            . '  request "posts:read" about no saved subject; asked in platform, decided in platform',
            ExplanationText::render($decision->explain()),
        );
    }

    /**
     * Every name is escaped: markup, quotes, backslashes, control and non-ASCII
     * characters never reach the text as they are, so no name can start a line
     * of its own.
     *
     * @return void
     */
    public function testEveryNameIsEscaped(): void
    {
        $hostile   = "<fg=red>x</>\n  [allow] forged: matched\u{202E}\"\\&";
        $statement = new StatementReference($hostile, 0, $hostile, $hostile, $hostile);
        $test      = new ConditionResult($hostile, $hostile, ConditionOutcome::UNRESOLVED, false, false, [$hostile]);
        $grant     = new GrantProvenance(GrantSource::ROLE_POLICY, $hostile, new Reference('user', $hostile), false, [$hostile], true, new Reference($hostile, '1'), $hostile);
        $request   = new ExplanationRequest($hostile, $hostile, new DecisionProvenance, new DecisionProvenance(new Reference('user', $hostile)));
        $decision  = Decision::allow(DecisionStage::ALLOW, [$statement], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statement, [$hostile => true], $hostile, $hostile, [], [$test], [$hostile]),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::REFUSED, null, [], $hostile),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, $hostile),
        ])->withEvidence(new DecisionEvidence([$grant], $request));

        $text = ExplanationText::render($decision->explain());

        self::assertStringNotContainsString('<', $text);
        self::assertStringNotContainsString('>', $text);
        self::assertStringNotContainsString('&', $text);
        self::assertStringNotContainsString("\u{202E}", $text);
        self::assertStringNotContainsString("\n  [allow] forged", $text);
        self::assertStringContainsString('\u003Cfg=red\u003Ex\u003C/\u003E\n  [allow] forged: matched\u202e\"\\\\\u0026', $text);
        self::assertSame(1, \preg_match_all('/^\S/m', $text));
    }

    /**
     * bare() and quoted() escape a name as a JSON string does, without and with
     * its quotes: a control character as its short JSON escape, or as `\uXXXX`
     * when it has none.
     *
     * @return void
     */
    public function testBareAndQuoted(): void
    {
        self::assertSame('posts:*', ExplanationText::bare('posts:*'));
        self::assertSame('"posts:*"', ExplanationText::quoted('posts:*'));
        self::assertSame('a/b \u003C\"\\\\', ExplanationText::bare('a/b <"\\'));
        self::assertSame('"\ufffd"', ExplanationText::quoted("\xB1"));
        self::assertSame('a\nb\tc\u0001', ExplanationText::bare("a\nb\tc\x01"));
    }

    /**
     * statement() names the policy, its key, the position, the sid and the
     * resource, each escaped, leaving out what the reference does not carry.
     *
     * @return void
     */
    public function testStatement(): void
    {
        self::assertSame('p#3', ExplanationText::statement(new StatementReference('p', 3)));
        self::assertSame('p[k]#0 sid="s" on "posts:1"', ExplanationText::statement(new StatementReference('p', 0, 'k', 's', 'posts:1')));
    }

    /**
     * A grant through a break-glass activation names the activation, quoted,
     * after the roles it came through and before its scope; any other grant
     * names none.
     *
     * @return void
     */
    public function testABreakGlassGrantNamesItsActivation(): void
    {
        $statement = new StatementReference('own', 0, 'key');
        $decision  = Decision::allow(DecisionStage::ALLOW, [$statement])->withEvidence(new DecisionEvidence([
            new GrantProvenance(GrantSource::BREAK_GLASS_PERMISSION, 'posts:edit', new Reference('user', '1'), false, ['responder'], true, null, null, "act\n1"),
            new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:edit', new Reference('user', '1'), false, ['responder'], true),
        ]));

        $text = ExplanationText::render($decision->explain());

        self::assertStringContainsString(
            "\n  grant break glass permission \"posts:edit\" to principal user:1 through role \"responder\" by break-glass activation \"act\\n1\" in platform\n",
            $text,
        );
        self::assertStringContainsString("\n  grant role permission \"posts:edit\" to principal user:1 through role \"responder\" in platform", $text);
        self::assertSame(1, \substr_count($text, 'by break-glass activation'));
    }

    /**
     * Return the provenance of a check about the first user, its identity the
     * second person, previewed by the ninth user, decided in the tenant and the
     * application.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance
     */
    private static function decidedIn(Reference $tenant, string $application): DecisionProvenance
    {
        return new DecisionProvenance(new Reference('user', '1'), new Reference('person', '2'), new Reference('user', '9'), $tenant, $application);
    }
}
