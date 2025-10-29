<?php

namespace Tests\Unit\Utopia\DNS\Message;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\DecodingException;
use Utopia\DNS\Message\Domain;
use PHPUnit\Framework\Attributes\DataProvider;

final class DomainTest extends TestCase
{
    public function testEncodeProducesExpectedWireFormat(): void
    {
        $encoded = Domain::encode('www.example.com');

        $this->assertSame("\x03www\x07example\x03com\x00", $encoded);
    }

    public function testEncodeTreatsSingleTrailingDotAsAbsolute(): void
    {
        $this->assertSame(
            Domain::encode('example.com'),
            Domain::encode('example.com.')
        );
    }

    public function testEncodeAllowsRootViaEmptyString(): void
    {
        $this->assertSame("\x00", Domain::encode(''));
    }

    public function testEncodeAllowsRootViaDot(): void
    {
        $this->assertSame("\x00", Domain::encode('.'));
    }

    public function testDecodeSimpleDomain(): void
    {
        $data = "\x03www\x07example\x03com\x00"; // "www.example.com"
        $offset = 0;

        $decoded = Domain::decode($data, $offset);

        $this->assertSame('www.example.com', $decoded);
        $this->assertSame(strlen($data), $offset);
    }

    public function testDecodeRootDomain(): void
    {
        $data = "\x00"; // root label
        $offset = 0;

        $decoded = Domain::decode($data, $offset);

        $this->assertSame('', $decoded);
        $this->assertSame(1, $offset);
    }

    public function testDecodeCompressionPointer(): void
    {
        $first = "\x05first\x07example\x03com\x00"; // "first.example.com"
        $pointer = "\xC0\x00"; // pointer back to offset 0
        $data = $first . $pointer;

        $offset = 0;
        $decoded = Domain::decode($data, $offset);
        $this->assertSame('first.example.com', $decoded);
        $this->assertSame(strlen($first), $offset);

        $decodedPointer = Domain::decode($data, $offset);
        $this->assertSame('first.example.com', $decodedPointer);
        $this->assertSame(strlen($first) + strlen($pointer), $offset);
    }

    public function testDecodePointerLoopRaisesException(): void
    {
        $data = "\xC0\x00"; // pointer loops to itself
        $offset = 0;

        $this->expectException(DecodingException::class);
        $this->expectExceptionMessage('Possible compression pointer loop');

        Domain::decode($data, $offset);
    }

    public function testDecodeTruncatedPointerRaisesException(): void
    {
        $data = "\xC0"; // pointer missing second byte
        $offset = 0;

        $this->expectException(DecodingException::class);
        $this->expectExceptionMessage('Truncated compression pointer');

        Domain::decode($data, $offset);
    }

    #[DataProvider('invalidDomainProvider')]
    public function testEncodeRejectsInvalidDomains(string $domain, string $expectedMessage): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);

        Domain::encode($domain);
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function invalidDomainProvider(): array
    {
        $longLabel = str_repeat('a', Domain::MAX_LABEL_LEN + 1);
        $tooManyLabels = implode('.', array_fill(0, Domain::MAX_LABELS + 1, 'a'));
        $maxLabel = str_repeat('a', Domain::MAX_LABEL_LEN);
        $overLengthDomain = implode('.', [$maxLabel, $maxLabel, $maxLabel, $maxLabel]);

        return [
            'consecutive dots' => ['www..example.com', 'Domain labels must not be empty'],
            'double trailing dot apex' => ['example..', 'Domain labels must not be empty'],
            'double trailing dot absolute' => ['example.com..', 'Domain labels must not be empty'],
            'at symbol label' => ['@', 'Domain label contains invalid characters'],
            'label too long' => ["$longLabel.com", "Label too long: $longLabel"],
            'too many labels' => [$tooManyLabels, 'Domain has too many labels: ' . (Domain::MAX_LABELS + 1)],
            'encoded length exceeds limit' => [
                $overLengthDomain,
                'Encoded domain exceeds maximum length of ' . Domain::MAX_DOMAIN_NAME_LEN . ' bytes'
            ],
        ];
    }
}
