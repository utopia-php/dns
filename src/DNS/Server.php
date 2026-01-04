<?php

namespace Utopia\DNS;

use Throwable;
use Utopia\DNS\Exception\Message\PartialDecodingException;
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
    protected Adapter $adapter;
    protected Resolver $resolver;

    /** @var array<int, callable> */
    protected array $errors = [];

    protected bool $debug = false;

    /**
     * Telemetry metrics
     */
    protected ?Histogram $duration = null;
    protected ?Counter $queriesTotal = null;
    protected ?Counter $responsesTotal = null;

    public function __construct(Adapter $adapter, Resolver $resolver)
    {
        $this->adapter = $adapter;
        $this->resolver = $resolver;
        $this->setTelemetry(new NoTelemetry());
    }

    /**
     * Set telemetry adapter
     *
     * @param Telemetry $telemetry
     */
    public function setTelemetry(Telemetry $telemetry): void
    {
        $this->duration = $telemetry->createHistogram(
            'dns.query.duration',
            's',
            null,
            ['ExplicitBucketBoundaries' => [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]]
        );

        // Initialize additional telemetry metrics
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

    /**
     * Set Debug Mode
     *
     * @param bool $status
     * @return self
     */
    public function setDebug(bool $status): self
    {
        $this->debug = $status;
        return $this;
    }

    /**
     * Handle Error
     *
     * @param Throwable $error
     * @return void
     */
    protected function handleError(Throwable $error): void
    {
        foreach ($this->errors as $handler) {
            call_user_func($handler, $error);
        }
    }

    /**
     * Handle packet
     *
     * @param string $buffer
     * @param string $ip
     * @param int $port
     *
     * @return string
     */
    protected function onPacket(string $buffer, string $ip, int $port): string
    {
        $span = Span::init('dns.packet');
        $span->set('client.ip', $ip);

        $question = null;
        $response = null;

        try {
            // 1. Parse Message.
            $decodeStart = microtime(true);
            try {
                $query = Message::decode($buffer);
            } catch (PartialDecodingException $e) {
                $this->handleError($e);

                $response = Message::response(
                    $e->getHeader(),
                    Message::RCODE_FORMERR,
                    authoritative: false
                );
                return $response->encode();
            } catch (Throwable $e) {
                $span->setError($e);
                $this->handleError($e);
                return '';
            }
            $decodeDuration = microtime(true) - $decodeStart;
            $this->duration?->record($decodeDuration, ['phase' => 'decode']);
            $span->set('dns.duration.decode', $decodeDuration);

            $question = $query->questions[0] ?? null;
            if ($question === null) {
                $response = Message::response(
                    $query->header,
                    Message::RCODE_FORMERR,
                    authoritative: false
                );
                return $response->encode();
            }

            $span->set('dns.question.name', $question->name);
            $span->set('dns.question.type', $question->type);

            $this->queriesTotal?->add(1, [
                'type' => $question->type ?? null,
            ]);

            // 2. Resolve query
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

            // 3. Encode response
            $encodeStart = microtime(true);
            try {
                return $response->encode();
            } catch (Throwable $e) {
                $span->setError($e);
                $this->handleError($e);

                $response = Message::response(
                    $query->header,
                    Message::RCODE_SERVFAIL,
                    questions: $query->questions,
                    authoritative: false
                );
                return $response->encode();
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

    public function start(): void
    {
        try {
            /** @phpstan-var \Closure(string $buffer, string $ip, int $port):string $onPacket */
            $onPacket = $this->onPacket(...);
            $this->adapter->onPacket($onPacket);
            $this->adapter->start();
        } catch (Throwable $error) {
            $this->handleError($error);
        }
    }
}
