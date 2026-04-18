<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Adapter;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\DNS\ProxyProtocol;
use Utopia\DNS\Resolver;
use Utopia\DNS\Server;

/**
 * Server subclass that captures the (ip, port) pair passed to each DNS
 * packet. The resolver interface intentionally does not see peer info —
 * this hook is how the tests assert on PROXY-resolved addresses.
 */
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

/**
 * @phpstan-type UdpCall array{buffer: string, ip: string, port: int, maxResponseSize: ?int}
 */
final class ServerTest extends TestCase
{
    public function testUdpDirectQueryPassesPeerAddressThrough(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);

        $server->start();

        $query = $this->buildQuery('example.com');
        $response = $adapter->deliverUdp($query, '203.0.113.9', 9876);

        $this->assertNotSame('', $response);
        $decoded = Message::decode($response);
        $this->assertSame('203.0.113.9', $server->lastIp);
        $this->assertSame(9876, $server->lastPort);
        $this->assertCount(1, $decoded->answers);
    }

    public function testUdpStripsPxyV1WhenProxyProtocolEnabled(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $query = $this->buildQuery('example.com');
        $preamble = "PROXY TCP4 198.51.100.7 10.0.0.1 55555 53\r\n";
        $adapter->deliverUdp($preamble . $query, '10.0.0.254', 4444);

        $this->assertSame('198.51.100.7', $server->lastIp);
        $this->assertSame(55555, $server->lastPort);
    }

    public function testUdpTreatsUnwrappedDatagramAsDirectWhenProxyEnabled(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $query = $this->buildQuery('example.com');
        $adapter->deliverUdp($query, '192.0.2.1', 12345);

        $this->assertSame('192.0.2.1', $server->lastIp);
        $this->assertSame(12345, $server->lastPort);
    }

    public function testUdpDropsMalformedProxyDatagram(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $errors = [];
        $server->error(function (\Throwable $e) use (&$errors) {
            $errors[] = $e;
        });
        $server->start();

        $query = $this->buildQuery('example.com');
        $response = $adapter->deliverUdp("PROXY TCP4 bogus 10.0.0.1 1 2\r\n" . $query, '10.0.0.254', 1);

        $this->assertSame('', $response);
        $this->assertNull($server->lastIp);
        $this->assertCount(1, $errors);
    }

    public function testTcpSingleFrameDeliveredAndResponded(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        $query = $this->buildQuery('example.com');
        $frame = pack('n', strlen($query)) . $query;

        $adapter->deliverTcp(1, $frame, '198.51.100.10', 40000);

        $sent = $adapter->sentTcp(1);
        $this->assertCount(1, $sent);
        $this->assertSame('198.51.100.10', $server->lastIp);
        $this->assertSame(40000, $server->lastPort);

        $response = $sent[0];
        $unpacked = unpack('n', substr($response, 0, 2));
        $this->assertIsArray($unpacked);
        $this->assertSame(strlen($response) - 2, $unpacked[1]);

        $decoded = Message::decode(substr($response, 2));
        $this->assertCount(1, $decoded->answers);
    }

    public function testTcpFrameDeliveredAcrossMultipleChunks(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        $query = $this->buildQuery('example.com');
        $frame = pack('n', strlen($query)) . $query;

        $chunks = str_split($frame, 3);
        foreach ($chunks as $i => $chunk) {
            $adapter->deliverTcp(7, $chunk, '203.0.113.1', 1234);

            if ($i < count($chunks) - 1) {
                $this->assertSame([], $adapter->sentTcp(7), 'response must not fire until frame complete');
            }
        }

        $this->assertCount(1, $adapter->sentTcp(7));
    }

    public function testTcpMultipleFramesInSingleChunk(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        $q1 = $this->buildQuery('a.example');
        $q2 = $this->buildQuery('b.example');
        $payload = pack('n', strlen($q1)) . $q1 . pack('n', strlen($q2)) . $q2;

        $adapter->deliverTcp(5, $payload, '203.0.113.2', 2345);

        $this->assertCount(2, $adapter->sentTcp(5));
    }

    public function testTcpConsumesProxyV1PreambleBeforeFraming(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $query = $this->buildQuery('example.com');
        $preamble = "PROXY TCP4 192.0.2.10 10.0.0.1 55000 443\r\n";
        $frame = pack('n', strlen($query)) . $query;

        $adapter->deliverTcp(10, $preamble . $frame, '10.0.0.254', 4444);

        $this->assertCount(1, $adapter->sentTcp(10));
        $this->assertSame('192.0.2.10', $server->lastIp);
        $this->assertSame(55000, $server->lastPort);
    }

    public function testTcpConsumesProxyV2PreambleBeforeFraming(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $addrPayload = inet_pton('198.51.100.5') . inet_pton('10.0.0.1') . pack('nn', 11000, 53);
        $preamble = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x11)
            . pack('n', strlen($addrPayload))
            . $addrPayload;
        $query = $this->buildQuery('example.com');
        $frame = pack('n', strlen($query)) . $query;

        $adapter->deliverTcp(11, $preamble . $frame, '10.0.0.254', 0);

        $this->assertCount(1, $adapter->sentTcp(11));
        $this->assertSame('198.51.100.5', $server->lastIp);
    }

    public function testTcpDirectConnectionWorksWhenProxyProtocolEnabled(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $query = $this->buildQuery('example.com');
        $frame = pack('n', strlen($query)) . $query;

        $adapter->deliverTcp(12, $frame, '203.0.113.20', 4000);

        $this->assertCount(1, $adapter->sentTcp(12));
        $this->assertSame('203.0.113.20', $server->lastIp);
    }

    public function testTcpClosesOnMalformedProxyPreamble(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        $adapter->deliverTcp(13, "PROXY TCP4 bogus 10.0.0.1 1 2\r\nrest", '10.0.0.254', 0);

        $this->assertTrue($adapter->wasClosed(13));
    }

    public function testTcpClosesOnOversizeBuffer(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        // Send a declared huge frame length; body won't fit past TCP_MAX_BUFFER_SIZE.
        $adapter->deliverTcp(14, pack('n', 65535) . str_repeat('A', Server::TCP_MAX_BUFFER_SIZE), '203.0.113.30', 1);

        $this->assertTrue($adapter->wasClosed(14));
    }

    public function testTcpClosesOnZeroLengthFrame(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->start();

        $adapter->deliverTcp(15, pack('n', 0), '203.0.113.31', 1);

        $this->assertTrue($adapter->wasClosed(15));
    }

    public function testOnTcpCloseClearsState(): void
    {
        $adapter = new FakeAdapter();
        $resolver = new EchoResolver();
        $server = new RecordingServer($adapter, $resolver);
        $server->setProxyProtocol(true);
        $server->start();

        // Start a partial PROXY preamble to allocate server-side state.
        $adapter->deliverTcp(16, 'PROXY TCP4 1', '10.0.0.254', 0);
        // Close connection.
        $adapter->closeConnection(16);

        // Re-use the same fd for a new connection. State must not leak.
        $query = $this->buildQuery('example.com');
        $frame = pack('n', strlen($query)) . $query;
        $adapter->deliverTcp(16, $frame, '203.0.113.40', 5000);

        $this->assertCount(1, $adapter->sentTcp(16));
        $this->assertSame('203.0.113.40', $server->lastIp);
    }

    private function buildQuery(string $name): string
    {
        $query = Message::query(new Question($name, Record::TYPE_A));
        return $query->encode();
    }
}

final class EchoResolver implements Resolver
{
    public ?string $lastIp = null;

    public ?int $lastPort = null;

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

/**
 * Test double that records the server's interactions with the adapter.
 * Tests simulate incoming traffic via deliverUdp() / deliverTcp() and
 * inspect sent bytes via sentTcp().
 */
final class FakeAdapter extends Adapter
{
    /** @var callable(string, string, int, ?int): string */
    public $onUdpPacket;

    /** @var callable(int, string, string, int): void */
    public $onTcpReceive;

    /** @var callable(int): void */
    public $onTcpClose;

    /** @var array<int, list<string>> */
    private array $sent = [];

    /** @var array<int, bool> */
    private array $closed = [];

    public function onWorkerStart(callable $callback): void
    {
        // No-op.
    }

    public function onUdpPacket(callable $callback): void
    {
        $this->onUdpPacket = $callback;
    }

    public function onTcpReceive(callable $callback): void
    {
        $this->onTcpReceive = $callback;
    }

    public function onTcpClose(callable $callback): void
    {
        $this->onTcpClose = $callback;
    }

    public function sendTcp(int $fd, string $data): void
    {
        $this->sent[$fd][] = $data;
    }

    public function closeTcp(int $fd): void
    {
        $this->closed[$fd] = true;
        \call_user_func($this->onTcpClose, $fd);
    }

    public function start(): void
    {
        // No-op for tests.
    }

    public function getName(): string
    {
        return 'fake';
    }

    public function deliverUdp(string $buffer, string $ip, int $port): string
    {
        return \call_user_func($this->onUdpPacket, $buffer, $ip, $port, 512);
    }

    public function deliverTcp(int $fd, string $bytes, string $ip, int $port): void
    {
        \call_user_func($this->onTcpReceive, $fd, $bytes, $ip, $port);
    }

    public function closeConnection(int $fd): void
    {
        $this->closed[$fd] = true;
        \call_user_func($this->onTcpClose, $fd);
        unset($this->sent[$fd]);
    }

    /** @return list<string> */
    public function sentTcp(int $fd): array
    {
        return $this->sent[$fd] ?? [];
    }

    public function wasClosed(int $fd): bool
    {
        return $this->closed[$fd] ?? false;
    }
}
