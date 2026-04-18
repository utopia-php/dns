<?php

namespace Utopia\DNS;

use Throwable;
use Utopia\DNS\Exception\Message\PartialDecodingException;
use Utopia\DNS\Exception\ProxyProtocol\DecodingException as ProxyDecodingException;
use Utopia\Span\Span;
use Utopia\Telemetry\Adapter as Telemetry;
use Utopia\Telemetry\Adapter\None as NoTelemetry;
use Utopia\Telemetry\Counter;
use Utopia\Telemetry\Histogram;

/**
 * Reference about DNS packet:
 *
 * HEADER
 * > 16 bits identificationField (1-65535. 0 means no ID). ID provided by client. Helps to match async responses. Usage may allow DNS Cache Poisoning
 * > 16 bits flagsField (0-65535). Flags contains:
 * > -- qr (0 = query, 1 = response). Tells if packet is query (request) or response
 * > -- opcode (0-15). Tells type of packet
 * > -- aa (0 = no, 1 = yes. Can only be 1 in response packet). Tells if server is authoritative for queried domain
 * > -- tc (0 = no, 1 = yes. Can only be 1 in response packet). Tells if message was truncated (when message is too long)
 * > -- rd (0 = no, 1 = yes). Tells if client wants recursive resolution of query
 * > -- ra (0 = no, 1 = yes. Can only be 1 in server-to-server communication). Tells if client supports recursive resolution of query
 * > -- z (0-7. Always 0, reserved for future). Gives extra padding, no intention yet
 * > -- rcode (0-15. Can only be 1-15 in response packet. Incomming packet always has 0). Tells response status
 * > 16 bits numberOfQuestions (0-65535)
 * > 16 bits numberOfAnswers (0-65535)
 * > 16 bits numberOfAuthorities (0-65535)
 * > 16 bits numberOfAdditionals (0-65535)
 *
 * QUESTIONS SECTION
 * > Each question contains:
 * > -- dynamic-length name. Includes domain name we are looking for. Split into labels. To get domain, join labels with dot symbol.
 * > -- -- Following pattern repeats:
 * > -- -- -- 8 bits labelLength (0-255). Defines length of label. We use it in next step
 * > -- -- -- X bits label. X length is labelLength.
 * > -- -- When labelLength and label are both 0, it's end of name.
 * > -- 16 bits type (0-65535). Tells what type of record we are asking for, like A, AAAA, or CNAME
 * > -- 16 bits class (0-65535). Usually always 1, meaning internet class
 * > This pattern repeats, as there can be multiple questions. Not sure what the separator is
 *
 * ANSWERS SECTION
 * > Follows same pattern as questions section.
 * > Each answer also has (at the end):
 * > -- 32 bits ttl. Time to live of the answer
 * > -- 16 bit length. Length of the answer data.
 * > -- X bits data X length is length from above. Gives answer itself. Structure changes based on type.
 *
 * AUTHORITIES SECTION
 * ADDITIONALS SECTION
 *
 * RFCs:
 * - RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035
 * - RFC 3596: https://datatracker.ietf.org/doc/html/rfc3596
 * - RFC 6844: https://datatracker.ietf.org/doc/html/rfc6844
 * - RFC 2782: https://datatracker.ietf.org/doc/html/rfc2782
 */

class Server
{
    /** RFC 1035: UDP replies are capped at 512 bytes (EDNS0 aside). */
    public const int UDP_MAX_RESPONSE_SIZE = 512;

    /** RFC 1035: TCP frames use a 2-byte length prefix, so max 65535 bytes. */
    public const int TCP_MAX_MESSAGE_SIZE = 65535;

    /**
     * Hard cap on per-connection TCP buffer size. Prevents slow-loris style
     * attacks from consuming unbounded memory while a preamble or frame is
     * being accumulated. Must fit at least one max-sized DNS frame plus a
     * PROXY v1 preamble (107 bytes).
     */
    public const int TCP_MAX_BUFFER_SIZE = 131072;

    protected Adapter $adapter;
    protected Resolver $resolver;

    /** @var array<int, callable> */
    protected array $errors = [];

    protected bool $debug = false;

    protected bool $enableProxyProtocol = false;

    /** @var array<int, string> Per-fd TCP receive buffer. */
    protected array $tcpBuffers = [];

    /** @var array<int, ProxyProtocolStream> Per-fd PROXY preamble resolver (only if enabled). */
    protected array $tcpProxyStreams = [];

    /** @var array<int, array{ip: string, port: int}> Per-fd effective client address (peer or PROXY-resolved). */
    protected array $tcpAddresses = [];

    protected ?Histogram $duration = null;
    protected ?Counter $queriesTotal = null;
    protected ?Counter $responsesTotal = null;

    public function __construct(Adapter $adapter, Resolver $resolver)
    {
        $this->adapter = $adapter;
        $this->resolver = $resolver;
        $this->setTelemetry(new NoTelemetry());
    }

    public function setTelemetry(Telemetry $telemetry): void
    {
        $this->duration = $telemetry->createHistogram(
            'dns.query.duration',
            's',
            null,
            ['ExplicitBucketBoundaries' => [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]]
        );

        $this->queriesTotal = $telemetry->createCounter('dns.queries.total');
        $this->responsesTotal = $telemetry->createCounter('dns.responses.total');
    }

    /**
     * Add Error Handler
     *
     * @param callable $handler
     * @return self
     */
    public function error(callable $handler): self
    {
        $this->errors[] = $handler;
        return $this;
    }

    /**
     * On Worker Start
     *
     * @param callable(Server $server, int $workerId): void $handler
     * @phpstan-param callable(Server $server, int $workerId): void $handler
     * @return self
     */
    public function onWorkerStart(callable $handler): self
    {
        $this->adapter->onWorkerStart(function (int $workerId) use ($handler) {
            \call_user_func($handler, $this, $workerId);
        });

        return $this;
    }

    public function setDebug(bool $status): self
    {
        $this->debug = $status;
        return $this;
    }

    /**
     * Expect a PROXY protocol (v1 or v2) preamble on each UDP datagram and
     * TCP connection. Traffic without a preamble is still handled as direct
     * DNS, so health checks and direct clients keep working.
     *
     * Only enable when the listener is reachable solely from trusted
     * proxies — untrusted clients can forge a PROXY preamble to spoof their
     * source address.
     */
    public function setProxyProtocol(bool $enabled): self
    {
        $this->enableProxyProtocol = $enabled;
        $this->adapter->setProxyProtocol($enabled);
        return $this;
    }

    protected function handleError(Throwable $error): void
    {
        foreach ($this->errors as $handler) {
            call_user_func($handler, $error);
        }
    }

    /**
     * Handle a complete DNS message.
     *
     * Called once per decoded query, regardless of transport (UDP or TCP).
     * Subclasses override this hook to customize message handling; by
     * default it runs the decode/resolve/encode pipeline against the
     * configured resolver. $ip and $port are the real client address
     * (already resolved from PROXY protocol when enabled).
     */
    protected function onMessage(string $buffer, string $ip, int $port, ?int $maxResponseSize = null): string
    {
        $span = Span::init('dns.packet');
        $span->set('client.ip', $ip);

        $question = null;
        $response = null;

        try {
            $decodeStart = microtime(true);
            try {
                $query = Message::decode($buffer);
            } catch (PartialDecodingException $e) {
                $this->handleError($e);

                $span->set('level', 'warn');
                $response = Message::response(
                    $e->getHeader(),
                    Message::RCODE_FORMERR,
                    authoritative: false
                );
                return $response->encode($maxResponseSize);
            } catch (Throwable $e) {
                $span->setError($e);
                $this->handleError($e);
                return '';
            }
            $decodeDuration = microtime(true) - $decodeStart;
            $this->duration?->record($decodeDuration, ['phase' => 'decode']);
            $span->set('dns.duration.decode', $decodeDuration);

            // RFC 1035: Only OPCODE 0 (QUERY) is supported
            if ($query->header->opcode !== 0) {
                $response = Message::response(
                    $query->header,
                    Message::RCODE_NOTIMP,
                    authoritative: false
                );
                return $response->encode($maxResponseSize);
            }

            $question = $query->questions[0] ?? null;
            if ($question === null) {
                $span->set('level', 'warn');
                $response = Message::response(
                    $query->header,
                    Message::RCODE_FORMERR,
                    authoritative: false
                );
                return $response->encode($maxResponseSize);
            }

            $span->set('dns.question.name', $question->name);
            $span->set('dns.question.type', $question->type);

            $this->queriesTotal?->add(1, [
                'type' => $question->type ?? null,
            ]);

            $resolveStart = microtime(true);
            try {
                $response = $this->resolver->resolve($query);
            } catch (Throwable $e) {
                $span->setError($e);
                $this->handleError($e);

                $response = Message::response(
                    $query->header,
                    Message::RCODE_SERVFAIL,
                    questions: $query->questions,
                    authoritative: false
                );
            }
            $resolveDuration = microtime(true) - $resolveStart;
            $this->duration?->record($resolveDuration, [
                'phase' => 'resolve',
                'responseCode' => $response->header->responseCode,
            ]);
            $span->set('dns.duration.resolve', $resolveDuration);

            $encodeStart = microtime(true);
            try {
                return $response->encode($maxResponseSize);
            } catch (Throwable $e) {
                $span->setError($e);
                $this->handleError($e);

                $response = Message::response(
                    $query->header,
                    Message::RCODE_SERVFAIL,
                    questions: $query->questions,
                    authoritative: false
                );
                return $response->encode($maxResponseSize);
            } finally {
                $encodeDuration = microtime(true) - $encodeStart;
                $this->duration?->record($encodeDuration, [
                    'phase' => 'encode',
                    'responseCode' => $response->header->responseCode
                ]);
                $span->set('dns.duration.encode', $encodeDuration);
            }
        } finally {
            if ($question !== null) {
                $this->responsesTotal?->add(1, [
                    'type' => $question->type ?? null,
                    'responseCode' => $response?->header->responseCode
                ]);
            }

            if ($response !== null) {
                $span->set('dns.response.code', $response->header->responseCode);
                $span->set('dns.response.answer_count', $response->header->answerCount);
            }
            $span->finish();
        }
    }

    /**
     * UDP adapter callback. Strips a PROXY preamble (if enabled) and
     * delegates to {@see onMessage()}.
     */
    private function dispatchUdp(string $buffer, string $ip, int $port, ?int $maxResponseSize): string
    {
        if ($this->enableProxyProtocol) {
            try {
                $header = ProxyProtocolStream::unwrapDatagram($buffer);
            } catch (ProxyDecodingException $e) {
                $this->handleError($e);
                return '';
            }

            if ($header !== null && $header->sourceAddress !== null && $header->sourcePort !== null) {
                $ip = $header->sourceAddress;
                $port = $header->sourcePort;
            }
        }

        return $this->onMessage($buffer, $ip, $port, $maxResponseSize);
    }

    /**
     * TCP adapter callback. Buffers bytes, consumes a PROXY preamble when
     * present, extracts length-prefixed DNS frames, and sends responses
     * back via the adapter.
     */
    private function dispatchTcpReceive(int $fd, string $bytes, string $ip, int $port): void
    {
        if (!isset($this->tcpBuffers[$fd])) {
            $this->tcpBuffers[$fd] = '';
            $this->tcpAddresses[$fd] = ['ip' => $ip, 'port' => $port];
            if ($this->enableProxyProtocol) {
                $this->tcpProxyStreams[$fd] = new ProxyProtocolStream();
            }
        }

        $buffer = $this->tcpBuffers[$fd] . $bytes;

        if (strlen($buffer) > self::TCP_MAX_BUFFER_SIZE) {
            $this->adapter->closeTcp($fd);
            return;
        }

        $stream = $this->tcpProxyStreams[$fd] ?? null;

        if ($stream !== null && $stream->state() === ProxyProtocolStream::STATE_UNRESOLVED) {
            try {
                $state = $stream->resolve($buffer);
            } catch (ProxyDecodingException $e) {
                $this->handleError($e);
                $this->adapter->closeTcp($fd);
                return;
            }

            if ($state === ProxyProtocolStream::STATE_UNRESOLVED) {
                $this->tcpBuffers[$fd] = $buffer;
                return;
            }

            $header = $stream->header();
            if ($header !== null && $header->sourceAddress !== null && $header->sourcePort !== null) {
                $this->tcpAddresses[$fd] = [
                    'ip' => $header->sourceAddress,
                    'port' => $header->sourcePort,
                ];
            }
        }

        while (strlen($buffer) >= 2) {
            $unpacked = unpack('n', substr($buffer, 0, 2));
            $frameLength = (is_array($unpacked) && is_int($unpacked[1] ?? null)) ? $unpacked[1] : 0;

            // RFC 1035 / 7766: 0-length frames are invalid; oversize frames are either misframed or hostile.
            if ($frameLength === 0 || $frameLength > self::TCP_MAX_MESSAGE_SIZE) {
                $this->adapter->closeTcp($fd);
                return;
            }

            if (strlen($buffer) < $frameLength + 2) {
                break;
            }

            $message = substr($buffer, 2, $frameLength);
            $buffer = substr($buffer, $frameLength + 2);

            $address = $this->tcpAddresses[$fd];
            $response = $this->onMessage($message, $address['ip'], $address['port'], self::TCP_MAX_MESSAGE_SIZE);

            if ($response !== '') {
                if (strlen($response) > self::TCP_MAX_MESSAGE_SIZE) {
                    // Truncation should have been applied already; if not, bail rather than corrupt framing.
                    $this->adapter->closeTcp($fd);
                    return;
                }
                $this->adapter->sendTcp($fd, pack('n', strlen($response)) . $response);
            }
        }

        $this->tcpBuffers[$fd] = $buffer;
    }

    private function dispatchTcpClose(int $fd): void
    {
        unset(
            $this->tcpBuffers[$fd],
            $this->tcpProxyStreams[$fd],
            $this->tcpAddresses[$fd],
        );
    }

    public function start(): void
    {
        try {
            $this->adapter->onUdpPacket($this->dispatchUdp(...));
            $this->adapter->onTcpReceive($this->dispatchTcpReceive(...));
            $this->adapter->onTcpClose($this->dispatchTcpClose(...));
            $this->adapter->start();
        } catch (Throwable $error) {
            $this->handleError($error);
        }
    }
}
