<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Adapter;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\Resolver;
use Utopia\DNS\Server;

final class ServerTest extends TestCase
{
    public function testMessageIsDecodedResolvedEncoded(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new Server($adapter, $resolver);
        $server->start();

        $query = $this->buildQuery('example.com');
        $response = $adapter->deliver($query, '203.0.113.9', 9876);

        $decoded = Message::decode($response);
        $this->assertCount(1, $decoded->answers);
        $this->assertSame('example.com', $decoded->answers[0]->name);
    }

    public function testPeerAddressIsForwardedToResolverHook(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        $query = $this->buildQuery('example.com');
        $adapter->deliver($query, '203.0.113.9', 9876);

        $this->assertSame('203.0.113.9', $server->lastIp);
        $this->assertSame(9876, $server->lastPort);
    }

    public function testMalformedMessageReturnsFormerr(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new Server($adapter, $resolver);
        $errors = [];
        $server->error(function (\Throwable $e) use (&$errors) {
            $errors[] = $e;
        });
        $server->start();

        // Minimal valid header (12 bytes) but with question count > 0 and no question section.
        $malformed = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $response = $adapter->deliver($malformed, '127.0.0.1', 1234);

        $decoded = Message::decode($response);
        $this->assertSame(Message::RCODE_FORMERR, $decoded->header->responseCode);
    }

    public function testNonQueryOpcodeReturnsNotimp(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new Server($adapter, $resolver);
        $server->start();

        // Opcode 2 (STATUS) in flags field.
        $packet = "\x12\x34\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        $response = $adapter->deliver($packet, '127.0.0.1', 1234);

        $decoded = Message::decode($response);
        $this->assertSame(Message::RCODE_NOTIMP, $decoded->header->responseCode);
    }

    public function testResolverExceptionReturnsServfail(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new ThrowingResolver();
        $server = new Server($adapter, $resolver);
        $errors = [];
        $server->error(function (\Throwable $e) use (&$errors) {
            $errors[] = $e;
        });
        $server->start();

        $query = $this->buildQuery('example.com');
        $response = $adapter->deliver($query, '127.0.0.1', 1234);

        $decoded = Message::decode($response);
        $this->assertSame(Message::RCODE_SERVFAIL, $decoded->header->responseCode);
        $this->assertCount(1, $errors);
    }

    public function testSetProxyProtocolPropagatesToAdapter(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new Server($adapter, $resolver);

        $this->assertFalse($adapter->hasProxyProtocol());
        $server->setProxyProtocol(true);
        $this->assertTrue($adapter->hasProxyProtocol());
        $server->setProxyProtocol(false);
        $this->assertFalse($adapter->hasProxyProtocol());
    }

    private function buildQuery(string $name): string
    {
        return Message::query(new Question($name, Record::TYPE_A))->encode();
    }
}

class RecordingServer extends Server
{
    public ?string $lastIp = null;

    public ?int $lastPort = null;

    protected function onMessage(string $buffer, string $ip, int $port, ?int $maxResponseSize = null): string
    {
        $this->lastIp = $ip;
        $this->lastPort = $port;
        return parent::onMessage($buffer, $ip, $port, $maxResponseSize);
    }
}

final class EchoResolver implements Resolver
{
    public function getName(): string
    {
        return 'echo';
    }

    public function resolve(Message $query): Message
    {
        return Message::response(
            header: $query->header,
            responseCode: Message::RCODE_NOERROR,
            questions: $query->questions,
            answers: [
                new Record(
                    name: $query->questions[0]->name,
                    type: Record::TYPE_A,
                    rdata: '127.0.0.1',
                    ttl: 60,
                ),
            ],
            authoritative: true,
        );
    }
}

final class ThrowingResolver implements Resolver
{
    public function getName(): string
    {
        return 'throwing';
    }

    public function resolve(Message $query): Message
    {
        throw new \RuntimeException('resolver failed');
    }
}

/**
 * Minimal transport-neutral adapter for Server unit tests: call
 * {@see deliver()} to simulate a message arriving on the wire and
 * receive the response the Server would send back.
 */
final class FakeAdapter extends Adapter
{
    /** @var callable(string, string, int, ?int): string */
    private $onMessage;

    public function onWorkerStart(callable $callback): void
    {
        // Not used in unit tests.
    }

    public function onMessage(callable $callback): void
    {
        $this->onMessage = $callback;
    }

    public function start(): void
    {
        // Tests drive the adapter via deliver(); no loop needed.
    }

    public function getName(): string
    {
        return 'fake';
    }

    public function deliver(string $buffer, string $ip, int $port, ?int $maxResponseSize = 512): string
    {
        return \call_user_func($this->onMessage, $buffer, $ip, $port, $maxResponseSize);
    }
}
