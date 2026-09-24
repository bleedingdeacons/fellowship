<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Core\UserAgent;

/**
 * Unit tests for {@see UserAgent}.
 *
 * The shape asserted here is the one an upstream's bot protection was
 * asked for — product, version, contact, deployment — so these tests
 * are deliberately literal about the punctuation. home_url() comes
 * from the wp-mocks WordPress stub group and answers
 * https://example.test/.
 */

test('the plugin identifies itself with name version contact and site', function () {
    expect(UserAgent::plugin())->toBe('Fellowship/9.9.9 (rest@aa-bristol.org; https://example.test)');
});

test('it builds the documented shape for any app', function () {
    expect(UserAgent::forApp('Widget', '1.2.3'))->toBe('Widget/1.2.3 (rest@aa-bristol.org; https://example.test)');
});

test('a missing version leaves out the slash', function () {
    // Better a product with no version than "Widget/" or an invented one.
    expect(UserAgent::forApp('Widget'))->toBe('Widget (rest@aa-bristol.org; https://example.test)');
});

test('an empty app name falls back to the plugin', function () {
    expect(UserAgent::forApp('', '1.0'))->toStartWith('Fellowship/1.0');
});

test('header breaking characters are stripped', function () {
    // A newline here would be header injection; a bracket or
    // semicolon would close the comment early and leave the
    // contact details dangling outside it.
    expect(UserAgent::forApp('Widget', "1.2.3\r\n(evil);"))->toBe('Widget/1.2.3 evil (rest@aa-bristol.org; https://example.test)');
});

test('the contact is the role address', function () {
    expect(UserAgent::CONTACT)->toBe('rest@aa-bristol.org');
});
