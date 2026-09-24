<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\DeviceTokenMinter;

/**
 * The bearer token a handset holds, and the value stored against its row.
 */

beforeEach(function () {
    $this->minter = new DeviceTokenMinter();
});

test('a minted token is recognised as one', function () {
    expect($this->minter->looksLikeToken($this->minter->mint()))->toBeTrue();
});

test('every token is different', function () {
    $tokens = [];
    for ($i = 0; $i < 50; $i++) {
        $tokens[] = $this->minter->mint();
    }

    expect(array_unique($tokens))->toHaveCount(50);
});

test('the stored value is not the token', function () {
    // A database dump must yield nothing usable. The row holds an
    // HMAC keyed on the site salt, so testing candidate tokens
    // offline needs wp-config.php as well as the dump.
    $token = $this->minter->mint();

    expect($this->minter->hash($token))->not->toBe($token);
    expect($this->minter->hash($token))->not->toContain($token);
});

test('hashing is stable', function () {
    // The lookup on every authenticated request depends on this.
    $token = $this->minter->mint();

    expect($this->minter->hash($token))->toBe($this->minter->hash($token));
});

test('somebody elses bearer token is rejected before the database', function (string $candidate) {
    // Checked with a regex before the lookup, so a request carrying a
    // WordPress application password or another plugin's JWT costs
    // nothing.
    expect($this->minter->looksLikeToken($candidate))->toBeFalse();
})->with([
    'empty'          => [''],
    'wrong prefix'   => ['rdt_' . str_repeat('a', 64)],
    'no prefix'      => [str_repeat('a', 64)],
    'too short'      => ['fdt_' . str_repeat('a', 32)],
    'too long'       => ['fdt_' . str_repeat('a', 128)],
    'not hex'        => ['fdt_' . str_repeat('z', 64)],
    'a jwt'          => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'],
]);

test('the bearer value is taken from the header', function (string $header, string $expected) {
    expect($this->minter->bearerFrom($header))->toBe($expected);
})->with([
    'plain'            => ['Bearer fdt_abc', 'fdt_abc'],
    'lower case'       => ['bearer fdt_abc', 'fdt_abc'],
    'padded'           => ['  Bearer   fdt_abc  ', 'fdt_abc'],
    'empty'            => ['', ''],
    'basic auth'       => ['Basic dXNlcjpwYXNz', ''],
    'no scheme'        => ['fdt_abc', ''],
    'two values'       => ['Bearer fdt_abc fdt_def', ''],
]);
