<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Subject;

/**
 * Console subject resolver contract (AUTHZ-11.5, N91).
 *
 * Turns the saved subject reference an operator types on the command line,
 * `authorization:why`'s `{subject}` argument, into the subject a check is
 * about: its principal and the identity behind it, with no tenant, no
 * application and no session. The command adds the tenant and application it is
 * given, and a console invocation never has the subject's browser session, so
 * no authentication requirement is met for it. Nothing is inferred from whoever
 * is signed in to the console.
 *
 * The shipped default, `ReferenceSubjectResolver`, loads the model a
 * `{morphType}:{key}` reference names and maps it to its principal and identity
 * through the bound subject resolver. An application whose principals and
 * identities that mapping cannot tell apart binds its own implementation on
 * this contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ConsoleSubjectResolver
{
    /**
     * Resolve the saved subject the reference names, with its principal and
     * identity and no tenant, application or session.
     *
     * A reference that is malformed, names nothing, names a model that cannot
     * be a subject, or names one that cannot be told apart from another is
     * refused, never guessed at.
     *
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    public function resolve(string $reference): Subject;
}
