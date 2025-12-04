<?php

namespace Tests\Unit\Utopia\DNS\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Validator\Name;

final class NameTest extends TestCase
{
    public function testValid(): void
    {
        $validator = new Name(Record::TYPE_CNAME);

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

        // Type that allows underscores in name
        $validator = new Name(Record::TYPE_SRV);
        $this->assertTrue($validator->isValid('example._tcp.com'), "Expected valid: example._tcp.com");
    }

    public function testInvalid(): void
    {
        $validator = new Name(Record::TYPE_CNAME);

        $invalidValues = [
            ['value' => 123, 'description' => Name::FAILURE_REASON_GENERAL],
            ['value' => '', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 256) . '.com', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 64) . '.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_LENGTH],
            ['value' => '-example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => 'example-.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => 'exa_mple.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => 'example..com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => '.example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => 'example.com..', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
            ['value' => 'exa mple.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE],
        ];

        foreach ($invalidValues as $value) {
            $this->assertFalse($validator->isValid($value['value']), "Expected invalid: {$value['value']}");
            $this->assertSame($value['description'], $validator->getDescription());
        }

        // Type that allows underscores in name
        $validator = new Name(Record::TYPE_TXT);

        $invalidValues = [
            ['value' => 123, 'description' => Name::FAILURE_REASON_GENERAL],
            ['value' => '', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 256) . '.com', 'description' => Name::FAILURE_REASON_INVALID_NAME_LENGTH],
            ['value' => str_repeat('a', 64) . '.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_LENGTH],
            ['value' => '-example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
            ['value' => 'example-.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
            ['value' => 'example..com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
            ['value' => '.example.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
            ['value' => 'example.com..', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
            ['value' => 'exa mple.com', 'description' => Name::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE],
        ];

        foreach ($invalidValues as $value) {
            $this->assertFalse($validator->isValid($value['value']), "Expected invalid: {$value['value']}");
            $this->assertSame($value['description'], $validator->getDescription());
        }
    }
}
