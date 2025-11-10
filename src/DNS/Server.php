<?php

namespace Utopia\DNS;

use Throwable;
use Utopia\Console;
use Utopia\DNS\Exception\Message\PartialDecodingException;
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
        if (empty($this->errors)) {
            // Default error handler
            Console::error('[ERROR] ' . $error->getMessage() . ' in ' . $error->getFile() . ' on line ' . $error->getLine() . "\n" . $error->getTraceAsString());
            return;
        }

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
        $startTime = microtime(true);
        Console::info("[PACKET] Received packet of " . strlen($buffer) . " bytes from $ip:$port");

        // 1. Parse Message.
        $decodeStart = microtime(true);
        try {
            $query = Message::decode($buffer);
        } catch (PartialDecodingException $e) {
            Console::error("[ERROR] Failed to decode packet: " . $e->getMessage());
            Console::error("[ERROR] Packet dump: " . bin2hex($buffer));
            Console::error("[ERROR] Processing time: " . (microtime(true) - $startTime) . "s");

            $this->handleError($e);

            $response = Message::response(
                $e->getHeader(),
                Message::RCODE_FORMERR,
                authoritative: false
            );
            return $response->encode();
        } catch (Throwable $e) {
            Console::error("[ERROR] Failed to decode packet: " . $e->getMessage());
            Console::error("[ERROR] Packet dump: " . bin2hex($buffer));
            Console::error("[ERROR] Processing time: " . (microtime(true) - $startTime) . "s");

            $this->handleError($e);

            // Returning SERVFAIL is unsafe here - just drop the packet
            return '';
        }

        $question = $query->questions[0] ?? null;
        if ($question === null) {
            $response = Message::response(
                $query->header,
                Message::RCODE_FORMERR,
                authoritative: false
            );
            return $response->encode();
        }

        $this->queriesTotal?->add(1, [
            'type' => $question->type ?? null,
        ]);
        $this->duration?->record(microtime(true) - $decodeStart, ['phase' => 'decode']);

        // 2. Resolve query
        $resolveStart = microtime(true);
        try {
            $response = $this->resolver->resolve($query);
        } catch (Throwable $e) {
            Console::error("[ERROR] Failed to resolve zone $question->name (Type: $question->type): " . $e->getMessage());
            Console::error("[ERROR] Packet dump: " . bin2hex($buffer));

            $this->handleError($e);

            $this->duration?->record(microtime(true) - $resolveStart, [
                'phase' => 'resolve',
                'responseCode' => Message::RCODE_SERVFAIL,
            ]);

            $response = Message::response(
                $query->header,
                Message::RCODE_SERVFAIL,
                questions: $query->questions,
                authoritative: false
            );
        }

        Console::info("[PACKET] DNS Header - ID: {$query->header->id}, Questions: {$query->header->questionCount}, Answers: {$query->header->answerCount}");

        if ($this->debug) {
            Console::info("[QUERY] Query for domain: $question->name (Type: $question->type)");
        }

        if (empty($response->answers)) {
            Console::warning("[RESPONSE] No answers found for $question->name ($question->type)");
        }

        // 3. Encode response
        $encodeStart = microtime(true);
        try {
            return $response->encode();
        } catch (Throwable $e) {
            Console::error("[ERROR] Failed to encode message: " . $e->getMessage());
            Console::error("[ERROR] Packet dump: " . bin2hex($buffer));

            $this->handleError($e);

            $response = Message::response(
                $query->header,
                Message::RCODE_SERVFAIL,
                questions: $query->questions,
                authoritative: false
            );
            return $response->encode();
        } finally {
            $this->responsesTotal?->add(1, [
                'type' => $question->type ?? null,
                'responseCode' => $response->header->responseCode
            ]);
            $this->duration?->record(microtime(true) - $encodeStart, [
                'phase' => 'encode',
                'responseCode' => $response->header->responseCode
            ]);

            $fullDuration = microtime(true) - $startTime;
            Console::info("[PACKET] Processing completed in $fullDuration\s");
            $this->duration?->record($fullDuration, ['phase' => 'full']);
        }
    }

    public function start(): void
    {
        try {
            Console::success('[DNS] Starting DNS Server...');
            Console::info('[CONFIG] Adapter: ' . $this->adapter->getName());
            Console::info('[CONFIG] Resolver: ' . $this->resolver->getName());
            Console::info('[CONFIG] Memory Limit: ' . ini_get('memory_limit'));
            Console::info('[CONFIG] Max Execution Time: ' . ini_get('max_execution_time') . 's');
            Console::info('[CONFIG] PHP Version: ' . PHP_VERSION);
            Console::info('[CONFIG] OS: ' . PHP_OS);
            Console::info('[CONFIG] Time: ' . date('Y-m-d H:i:s T'));
            Console::info('[CONFIG] Debug Mode: ' . ($this->debug ? 'Enabled' : 'Disabled'));

            Console::success('[DNS] Server is ready to accept connections');

            $this->adapter->onPacket($this->onPacket(...));
            $this->adapter->start();
        } catch (Throwable $error) {
            $this->handleError($error);
        }
    }
}
