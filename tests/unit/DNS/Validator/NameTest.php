<?php

namespace Tests\Unit\Utopia\DNS\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Validator\Name;

final class NameTest extends TestCase
{
    public function testValid(): void
    {
        $validator = new Name();

        $validValues = [
            'example',
            'example.com',
            'EXAMPLE.COM',
            'a-b.com',
            'a123.example-domain.org',
            'xn--d1acufc.xn--p1ai',
            '123.com',
            'example.com.',
            str_repeat('a', 63) . '.com',
        ];

        foreach ($validValues as $value) {
            $this->assertTrue($validator->isValid($value), "Expected valid: {$value}");
        }
    }

    public function testInvalid(): void
    {
        $validator = new Name();

        $invalidValues = [
            '',
            '-example.com',
            'example-.com',
            'exa_mple.com',
            'example..com',
            str_repeat('a', 64) . '.com',
            123,
            '.example.com',
            'example.com..',
            'exa mple.com',
        ];

        foreach ($invalidValues as $value) {
            $this->assertFalse($validator->isValid($value), 'Expected invalid value');
            $this->assertSame('Invalid name for DNS record', $validator->getDescription());
        }

    }
}
