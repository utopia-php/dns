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
            ['value' => 123, 'description' => Name::FAILURE_REASON_GENERAL],
            ['value' => '', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 256) . '.com', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 64) . '.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_LENGTH],
            ['value' => '-example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => 'example-.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => 'exa_mple.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => 'example..com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => '.example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => 'example.com..', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
            ['value' => 'exa mple.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS],
        ];

        foreach ($invalidValues as $value) {
            $this->assertFalse($validator->isValid($value['value']), "Expected invalid: {$value['value']}");
            $this->assertSame($value['description'], $validator->getDescription());
        }

    }
}
