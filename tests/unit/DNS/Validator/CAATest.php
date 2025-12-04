<?php

namespace Tests\Unit\Utopia\DNS\Validator;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Validator\CAA;

final class CAATest extends TestCase
{
    public function testValid(): void
    {
        $validator = new CAA();
        
        $validValues = [
            '0 issue "letsencrypt.org"',
            '128 issuewild "certainly.com;account=123456;validationmethods=dns-01"',
            '0 issuewild "certainly.com"',
            '0 iodef "mailto:security@example.com"',
            '0 issue ";"',
        ];
        
        foreach ($validValues as $value) {
            $this->assertTrue($validator->isValid($value), "Expected valid: {$value}");
        }
    }

    public function testInvalid(): void
    {
        $validator = new CAA();
        
        $invalidValues = [
            ['value' => 'issue "letsencrypt.org"', 'description' => 'Invalid format'],
            ['value' => '256 issue "letsencrypt.org"', 'description' => 'Invalid flags'],
            ['value' => '0 issue letsencrypt.org', 'description' => 'Invalid value'],
            ['value' => '0 issue ""', 'description' => 'Invalid value'],
        ];
        
        foreach ($invalidValues as $invalidValue) {
            $this->assertFalse($validator->isValid($invalidValue['value']), "Expected invalid: {$invalidValue['value']}");
            $this->assertSame("CAA verification failed. {$invalidValue['description']}.", $validator->getDescription());
        }
    }
}