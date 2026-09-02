<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Fellowship\Auth\DeviceTokenMinter;
use PHPUnit\Framework\TestCase;

/**
 * The bearer token a handset holds, and the value stored against its row.
 */
final class DeviceTokenMinterTest extends TestCase
{
    private DeviceTokenMinter $minter;

    protected function setUp(): void
    {
        $this->minter = new DeviceTokenMinter();
    }

    public function testAMintedTokenIsRecognisedAsOne(): void
    {
        self::assertTrue($this->minter->looksLikeToken($this->minter->mint()));
    }

    public function testEveryTokenIsDifferent(): void
    {
        $tokens = [];
        for ($i = 0; $i < 50; $i++) {
            $tokens[] = $this->minter->mint();
        }

        self::assertCount(50, array_unique($tokens));
    }

    public function testTheStoredValueIsNotTheToken(): void
    {
        // A database dump must yield nothing usable. The row holds an
        // HMAC keyed on the site salt, so testing candidate tokens
        // offline needs wp-config.php as well as the dump.
        $token = $this->minter->mint();

        self::assertNotSame($token, $this->minter->hash($token));
        self::assertStringNotContainsString($token, $this->minter->hash($token));
    }

    public function testHashingIsStable(): void
    {
        // The lookup on every authenticated request depends on this.
        $token = $this->minter->mint();

        self::assertSame($this->minter->hash($token), $this->minter->hash($token));
    }

    /**
     * @dataProvider notOurTokens
     */
    public function testSomebodyElsesBearerTokenIsRejectedBeforeTheDatabase(string $candidate): void
    {
        // Checked with a regex before the lookup, so a request carrying a
        // WordPress application password or another plugin's JWT costs
        // nothing.
        self::assertFalse($this->minter->looksLikeToken($candidate));
    }

    /** @return array<string, array{0: string}> */
    public static function notOurTokens(): array
    {
        return [
            'empty'          => [''],
            'wrong prefix'   => ['rdt_' . str_repeat('a', 64)],
            'no prefix'      => [str_repeat('a', 64)],
            'too short'      => ['fdt_' . str_repeat('a', 32)],
            'too long'       => ['fdt_' . str_repeat('a', 128)],
            'not hex'        => ['fdt_' . str_repeat('z', 64)],
            'a jwt'          => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'],
        ];
    }

    /**
     * @dataProvider headers
     */
    public function testTheBearerValueIsTakenFromTheHeader(string $header, string $expected): void
    {
        self::assertSame($expected, $this->minter->bearerFrom($header));
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function headers(): array
    {
        return [
            'plain'            => ['Bearer fdt_abc', 'fdt_abc'],
            'lower case'       => ['bearer fdt_abc', 'fdt_abc'],
            'padded'           => ['  Bearer   fdt_abc  ', 'fdt_abc'],
            'empty'            => ['', ''],
            'basic auth'       => ['Basic dXNlcjpwYXNz', ''],
            'no scheme'        => ['fdt_abc', ''],
            'two values'       => ['Bearer fdt_abc fdt_def', ''],
        ];
    }
}
