<?php

namespace Tests\E2E\Utopia\DNS\Resolver\Http;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Http\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver\Http\Google;

final class GoogleTest extends TestCase
{
    public function testResolveGoogleAWithPost(): void
    {
        $resolver = new Google();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_A, $record->type);
        $this->assertSame('google.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
    }

    public function testResolveGoogleAWithGet(): void
    {
        $resolver = new Google(useBackup: false, method: Client::METHOD_GET);

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_A, $record->type);
        $this->assertSame('google.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
    }

    public function testResolveGoogleAAAA(): void
    {
        $resolver = new Google();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_AAAA
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_AAAA, $record->type);
        $this->assertSame('google.com', $record->name);
        $this->assertNotFalse(filter_var($record->rdata, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
    }

    public function testResolveMXRecord(): void
    {
        $resolver = new Google();

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'google.com',
                type: Record::TYPE_MX
            )
        ));

        $this->assertNotEmpty($response->answers);
        $this->assertInstanceOf(Record::class, $response->answers[0] ?? null);

        /** @var Record $record */
        $record = $response->answers[0];
        $this->assertSame(Record::TYPE_MX, $record->type);
        $this->assertSame('google.com', $record->name);
        $this->assertNotNull($record->priority);
    }

    public function testResolveWithBackupEndpoint(): void
    {
        $resolver = new Google(useBackup: true);

        $this->assertSame(Google::ENDPOINT_BACKUP, $resolver->getClient()->getEndpoint());

        $response = $resolver->resolve(Message::query(
            new Question(
                name: 'example.com',
                type: Record::TYPE_A
            )
        ));

        $this->assertNotEmpty($response->answers);
    }

    public function testGetName(): void
    {
        $resolver = new Google();
        $this->assertStringContainsString('Google HTTP', $resolver->getName());
        $this->assertStringContainsString(Google::ENDPOINT_PRIMARY, $resolver->getName());

        $resolverBackup = new Google(useBackup: true);
        $this->assertStringContainsString(Google::ENDPOINT_BACKUP, $resolverBackup->getName());
    }

    public function testEndpointConstants(): void
    {
        $this->assertSame('https://dns.google/dns-query', Google::ENDPOINT_PRIMARY);
        $this->assertSame('https://dns.google/dns-query', Google::ENDPOINT_BACKUP);
    }
}
