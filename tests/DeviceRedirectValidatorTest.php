<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\DeviceRedirectValidator;

/**
 * The allow-list that decides where a sign-in code may be sent.
 *
 * This value arrives on an unauthenticated route and ends up as a
 * `Location:` header carrying a credential, so each refusal below is a
 * way somebody could otherwise have that credential delivered to them.
 */

beforeEach(function () {
    $this->validator = new DeviceRedirectValidator();
});

test('the apps own scheme is allowed', function () {
    expect($this->validator->isAllowed('link://auth'))->toBeTrue();
});

test('a loopback listener is allowed for development', function () {
    expect($this->validator->isAllowed('http://127.0.0.1:8765'))->toBeTrue();
});

test('these are refused', function (string $uri) {
    expect($this->validator->isAllowed($uri))->toBeFalse();
})->with([
    'empty'                  => [''],
    'somebody elses site'    => ['https://example.com/collect'],
    'a different app scheme' => ['hand://auth'],
    'wrong host'             => ['link://elsewhere'],
    // A fragment can carry a second URI past naive parsing.
    'fragment smuggling'     => ['link://auth#https://example.com'],
    // Credentials in the authority are another way to make a URI
    // read differently to a parser than to a human.
    'userinfo'               => ['link://user@auth'],
    // We append the code ourselves; a query already on the URI is
    // an attempt to control what the app sees alongside it.
    'query already present'  => ['link://auth?next=https://example.com'],
    'port on the app scheme' => ['link://auth:8080'],
    // Privileged ports need root, so a developer's listener is
    // never legitimately there.
    'privileged loopback'    => ['http://127.0.0.1:80'],
    'non-loopback http'      => ['http://192.168.1.10:8765'],
    'no scheme'              => ['auth'],
]);

test('params are appended as a query string', function () {
    expect($this->validator->withParams('link://auth', ['code' => 'abc123']))->toBe('link://auth?code=abc123');
});

test('params are encoded', function () {
    $result = $this->validator->withParams('link://auth', ['error' => 'not a member']);

    expect($result)->toContain('error=not%20a%20member');
});
