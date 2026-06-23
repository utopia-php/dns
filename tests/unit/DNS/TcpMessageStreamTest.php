<?php

namespace Tests\Unit\Utopia\DNS;

use PHPUnit\Framework\TestCase;
use Utopia\DNS\Exception\Message\DecodingException as MessageDecodingException;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\DNS\ProxyProtocol;
use Utopia\DNS\TcpMessageStream;

final class TcpMessageStreamTest extends TestCase
{
    public function testSingleFrameEmitsOneMessageWithPeerAddress(): void
    {
        $stream = new TcpMessageStream('198.51.100.10', 40000);
        $message = 'HELLO-DNS';
        $frame = pack('n', strlen($message)) . $message;

        $results = iterator_to_array($stream->feed($frame), preserve_keys: false);

        $this->assertCount(1, $results);
        $this->assertSame([$message, '198.51.100.10', 40000], $results[0]);
    }

    public function testFramesSplitAcrossChunksAccumulate(): void
    {
        $stream = new TcpMessageStream('203.0.113.1', 1234);
        $message = str_repeat('A', 40);
        $frame = pack('n', strlen($message)) . $message;

        $pieces = str_split($frame, 5);
        $collected = [];

        foreach ($pieces as $i => $piece) {
            foreach ($stream->feed($piece) as $result) {
                $collected[] = $result;
            }
            if ($i < count($pieces) - 1) {
                $this->assertSame([], $collected, "should not emit before frame complete (piece {$i})");
            }
        }

        $this->assertCount(1, $collected);
        $this->assertSame($message, $collected[0][0]);
    }

    public function testMultipleFramesInSingleFeedEmitMultipleMessages(): void
    {
        $stream = new TcpMessageStream('1.2.3.4', 53);
        $payload = '';
        foreach (['ONE', 'TWO', 'THREE'] as $m) {
            $payload .= pack('n', strlen($m)) . $m;
        }

        $results = iterator_to_array($stream->feed($payload), preserve_keys: false);

        $this->assertCount(3, $results);
        $this->assertSame('ONE', $results[0][0]);
        $this->assertSame('TWO', $results[1][0]);
        $this->assertSame('THREE', $results[2][0]);
    }

    public function testZeroLengthFrameThrows(): void
    {
        $stream = new TcpMessageStream('1.2.3.4', 53);

        $this->expectException(MessageDecodingException::class);
        foreach ($stream->feed(pack('n', 0)) as $_) {
            // consume generator
        }
    }

    public function testOversizeFrameThrows(): void
    {
        $stream = new TcpMessageStream('1.2.3.4', 53);

        $this->expectException(MessageDecodingException::class);
        foreach ($stream->feed(pack('n', TcpMessageStream::MAX_MESSAGE_SIZE + 1)) as $_) {
        }
    }

    public function testBufferOverflowThrows(): void
    {
        $stream = new TcpMessageStream('1.2.3.4', 53, enableProxyProtocol: true);

        // PROXY preamble is pending (not resolved), so no framing runs. Feed
        // more bytes than the buffer cap — should reject.
        $this->expectException(MessageDecodingException::class);
        foreach ($stream->feed(str_repeat('x', TcpMessageStream::MAX_BUFFER_SIZE + 1)) as $_) {
        }
    }

    public function testProxyV1PreambleUpdatesPeerAddress(): void
    {
        $stream = new TcpMessageStream('10.0.0.254', 443, enableProxyProtocol: true);

        $preamble = "PROXY TCP4 192.0.2.10 10.0.0.1 55000 443\r\n";
        $message = 'DNS-PAYLOAD';
        $frame = pack('n', strlen($message)) . $message;

        $results = iterator_to_array($stream->feed($preamble . $frame), preserve_keys: false);

        $this->assertCount(1, $results);
        $this->assertSame($message, $results[0][0]);
        $this->assertSame('192.0.2.10', $results[0][1]);
        $this->assertSame(55000, $results[0][2]);
    }

    public function testProxyV2PreambleUpdatesPeerAddress(): void
    {
        $stream = new TcpMessageStream('10.0.0.254', 0, enableProxyProtocol: true);

        $addrPayload = inet_pton('198.51.100.5') . inet_pton('10.0.0.1') . pack('nn', 11000, 53);
        $preamble = ProxyProtocol::V2_SIGNATURE
            . chr(0x21)
            . chr(0x11)
            . pack('n', strlen($addrPayload))
            . $addrPayload;

        $message = 'DNS-MESSAGE';
        $frame = pack('n', strlen($message)) . $message;

        $results = iterator_to_array($stream->feed($preamble . $frame), preserve_keys: false);

        $this->assertCount(1, $results);
        $this->assertSame('198.51.100.5', $results[0][1]);
    }

    public function testDirectConnectionWorksWhenProxyEnabled(): void
    {
        $stream = new TcpMessageStream('203.0.113.20', 4000, enableProxyProtocol: true);

        $message = 'DNS-PAYLOAD';
        $frame = pack('n', strlen($message)) . $message;

        $results = iterator_to_array($stream->feed($frame), preserve_keys: false);

        $this->assertCount(1, $results);
        $this->assertSame('203.0.113.20', $results[0][1]);
    }

    public function testMalformedProxyPreambleThrows(): void
    {
        $stream = new TcpMessageStream('10.0.0.254', 0, enableProxyProtocol: true);

        $this->expectException(ProxyDecodingException::class);
        foreach ($stream->feed("PROXY TCP4 bogus 10.0.0.1 1 2\r\nrest") as $_) {
        }
    }

    public function testPeerAddressAccessors(): void
    {
        $stream = new TcpMessageStream('1.2.3.4', 5678);

        $this->assertSame('1.2.3.4', $stream->peerIp());
        $this->assertSame(5678, $stream->peerPort());
    }

    public function testPartialPreambleKeepsBufferForNextCall(): void
    {
        $stream = new TcpMessageStream('10.0.0.254', 0, enableProxyProtocol: true);

        $preamble = "PROXY TCP4 192.0.2.10 10.0.0.1 55000 443\r\n";
        $message = 'DNS';
        $frame = pack('n', strlen($message)) . $message;

        $pieces = str_split($preamble . $frame, 4);
        $collected = [];
        foreach ($pieces as $piece) {
            foreach ($stream->feed($piece) as $result) {
                $collected[] = $result;
            }
        }

        $this->assertCount(1, $collected);
        $this->assertSame('192.0.2.10', $collected[0][1]);
    }
}
