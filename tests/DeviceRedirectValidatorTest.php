<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\DeviceRedirectValidator;
use PHPUnit\Framework\TestCase;

/**
 * The allow-list that decides where a sign-in code may be sent.
 *
 * This value arrives on an unauthenticated route and ends up as a
 * `Location:` header carrying a credential, so each refusal below is a
 * way somebody could otherwise have that credential delivered to them.
 */
final class DeviceRedirectValidatorTest extends TestCase
{
    private DeviceRedirectValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new DeviceRedirectValidator();
    }

    public function testTheAppsOwnSchemeIsAllowed(): void
    {
        self::assertTrue($this->validator->isAllowed('link://auth'));
    }

    public function testALoopbackListenerIsAllowedForDevelopment(): void
    {
        self::assertTrue($this->validator->isAllowed('http://127.0.0.1:8765'));
    }

    /**
     * @dataProvider refused
     */
    public function testTheseAreRefused(string $uri): void
    {
        self::assertFalse($this->validator->isAllowed($uri));
    }

    /** @return array<string, array{0: string}> */
    public static function refused(): array
    {
        return [
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
        ];
    }

    public function testParamsAreAppendedAsAQueryString(): void
    {
        self::assertSame(
            'link://auth?code=abc123',
            $this->validator->withParams('link://auth', ['code' => 'abc123']),
        );
    }

    public function testParamsAreEncoded(): void
    {
        $result = $this->validator->withParams('link://auth', ['error' => 'not a member']);

        self::assertStringContainsString('error=not%20a%20member', $result);
    }
}
