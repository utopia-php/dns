<?php

namespace Utopia\DNS;

use Utopia\CLI\Console;
use Throwable;
use Utopia\Telemetry\Adapter as Telemetry;
use Utopia\Telemetry\Adapter\None as NoTelemetry;
use Utopia\Telemetry\Counter;
use Utopia\Telemetry\Histogram;

/**
 * Refference about DNS packet:
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
 * > Each question contians:
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
 * > -- 32 bits ttl. Time to live of the naswer
 * > -- 16 bit length. Length of the answer data.
 * > -- X bits data X length is length from above. Gives answer itself. Structure changes based on type.
 *
 * AUTHORITIES SECTION
 * ADDITIONALS SECTION
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
    protected ?Histogram $resolveDuration = null;
    protected ?Counter $failuresTotal = null;
    protected ?Counter $incomingQueriesTotal = null;
    protected ?Counter $responseRcodesTotal = null;
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
     * @param  Telemetry  $telemetry
     */
    public function setTelemetry(Telemetry $telemetry): void
    {
        $this->resolveDuration = $telemetry->createHistogram(
            'dns.resolve.duration',
            's',
            null,
            ['ExplicitBucketBoundaries' => [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]]
        );

        $this->failuresTotal = $telemetry->createCounter('dns.resolve.failure');

        // Initialize additional telemetry metrics
        $this->incomingQueriesTotal = $telemetry->createCounter('dns.incoming.queries.total');
        $this->responseRcodesTotal = $telemetry->createCounter('dns.response.rcodes.total');
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

            $this->adapter->onPacket(function (string $buffer, string $ip, int $port) {
                $startTime = microtime(true);
                try {
                    Console::info("[PACKET] Received packet of " . strlen($buffer) . " bytes from {$ip}:{$port}");

                    // Track incoming query
                    $this->incomingQueriesTotal?->add(1);

                    // Parse header information for better debugging
                    $header = unpack('nid/nflags/nquestions/nanswers/nauthorities/nadditionals', substr($buffer, 0, 12));
                    if (!$header) {
                        throw new \Exception('Invalid header');
                    }

                    Console::info("[PACKET] DNS Header - ID: {$header['id']}, Questions: {$header['questions']}, Answers: {$header['answers']}");

                    // Parse question domain
                    $domain = "";
                    $offset = 12;
                    while ($offset < strlen($buffer)) {
                        // Check for at least 1 byte for label length
                        if (($offset + 1) > strlen($buffer)) {
                            throw new \Exception('Malformed packet: not enough bytes for label length');
                        }
                        $labelLength = ord($buffer[$offset]);
                        Console::info("[PACKET] Processing label at offset {$offset}, length: {$labelLength}");
                        // End of question (zero label)
                        if ($labelLength === 0) {
                            $offset += 1;
                            Console::info("[PACKET] End of domain name found at offset " . ($offset));
                            break;
                        }
                        // Check for enough bytes for label
                        if (($offset + 1 + $labelLength) > strlen($buffer)) {
                            throw new \Exception('Malformed packet: not enough bytes for label');
                        }
                        $label = substr($buffer, $offset + 1, $labelLength);
                        Console::info("[PACKET] Found label: {$label}");
                        if (empty($domain)) {
                            $domain .= $label;
                        } else {
                            $domain .= '.' . $label;
                        }
                        // Skip to next label length
                        $offset += 1 + $labelLength;
                    }
                    // After domain, there should be 4 bytes for type/class
                    if (($offset + 4) > strlen($buffer)) {
                        throw new \Exception('Malformed packet: not enough bytes for question type/class');
                    }
                    $unpacked = unpack('ntype/nclass', substr($buffer, $offset, 4));
                    $offset += 4;
                    $typeByte = $unpacked['type'] ?? 0;
                    $classByte = $unpacked['class'] ?? 0;

                    $type = match ($typeByte) {
                        1 => 'A',
                        5 => 'CNAME',
                        15 => 'MX',
                        16 => 'TXT',
                        28 => 'AAAA',
                        33 => 'SRV',
                        257 => 'CAA',
                        2 => 'NS',
                        default => 'A'
                    };

                    $question = [
                        'name' => $domain,
                        'type' => $type
                    ];

                    if ($this->debug) {
                        Console::info("[QUERY] Query for domain: {$domain} (Type: {$type})");
                    }

                    $answers = $this->resolve($question);

                    if (empty($answers)) {
                        Console::warning("[RESPONSE] No answers found for {$domain} ({$type})");
                    }

                    // Track responses (total)
                    $this->responsesTotal?->add(1);

                    // Determine and track response code
                    $responseLabel = empty($answers) ? 'NXDOMAIN' : 'NOERROR';
                    $this->responseRcodesTotal?->add(1, ['rcode' => $responseLabel]);

                    // Build response
                    $response = '';

                    // Copy the transaction ID
                    $response .= \substr($buffer, 0, 2);

                    // Construct the flags field more explicitly
                    $qr = 1;                                // Response
                    $opcode = 0;                            // Standard query
                    $aa = 1;                                // Authoritative
                    $tc = 0;                                // Not truncated
                    $rd = ($header['flags'] >> 8) & 1;      // Get RD from request
                    $ra = 0;                                // Recursion not available (or available, change as needed)
                    $z = 0;                                 // Zero
                    $rcode = empty($answers) ? 3 : 0;       // response code

                    $flags = ($qr << 15) | ($opcode << 11) | ($aa << 10) | ($tc << 9) | ($rd << 8) | ($ra << 7) | ($z << 4) | $rcode;
                    $response .= pack('n', $flags);

                    // Copy the question count
                    $response .= \substr($buffer, 4, 2);

                    // Set the answer, authority, and additional records count (initially 0)
                    $response .= pack('nnn', \count($answers), 0, 0);

                    // Copy questions section
                    $response .= \substr($buffer, 12, $offset - 12);

                    // Add answers section
                    foreach ($answers as $answer) {
                        $response .= chr(192) . chr(12); // 192 indicates this is pointer, 12 is offset to question.
                        // Pack the answer's type, not the question type
                        $response .= pack('nn', $answer->getType(), $classByte);
                        /**
                         * @var string $type
                         */
                        $type = $answer->getTypeName();
                        $response .= match ($type) {
                            'A' => $this->encodeIP($answer->getRdata(), $answer->getTTL()),
                            'AAAA' => $this->encodeIPv6($answer->getRdata(), $answer->getTTL()),
                            'CNAME' => $this->encodeDomain($answer->getRdata(), $answer->getTTL()),
                            'NS' => $this->encodeDomain($answer->getRdata(), $answer->getTTL()),
                            'TXT' => $this->encodeText($answer->getRdata(), $answer->getTTL()),
                            'CAA' => $this->encodeCAA($answer->getRdata(), $answer->getTTL()),
                            'MX' => $this->encodeMx($answer->getRdata(), $answer->getTTL(), $answer->getPriority() ?? 0),
                            'SRV' => $this->encodeSrv($answer->getRdata(), $answer->getTTL(), $answer->getPriority() ?? 0, $answer->getWeight() ?? 0, $answer->getPort() ?? 0),
                            default => ''
                        };
                    }

                    $processingTime = (microtime(true) - $startTime);
                    $this->resolveDuration?->record($processingTime, ['type' => $type]);
                    Console::info("[PACKET] Processing completed in {$processingTime}s");

                    if (empty($response)) {
                        Console::warning("[PACKET] Generated empty response for {$domain} ({$type})");
                    }

                    return $response;
                } catch (Throwable $error) {
                    $errorCategory = $this->categorizeError($error->getMessage());
                    $this->failuresTotal?->add(1, ['error' => $errorCategory]);
                    Console::error("[ERROR] Failed to process packet: " . $error->getMessage());
                    Console::error("[ERROR] Packet dump: " . bin2hex($buffer));
                    Console::error("[ERROR] Processing time: " . ((microtime(true) - $startTime) * 1000) . "ms");
                    $this->handleError($error);
                    return '';
                }
            });

            $this->adapter->start();
        } catch (Throwable $error) {
            $this->handleError($error);
        }
    }

    /**
     * Resolve domain name to IP by record type
     *
     * @param array<string, string> $question
     * @return array<int, \Utopia\DNS\Record>
     */
    protected function resolve(array $question): array
    {
        return $this->resolver->resolve($question);
    }

    protected function encodeIP(string $ip, int $ttl): string
    {
        $result = \pack('Nn', $ttl, 4);

        $binaryIP = inet_pton($ip);
        if ($binaryIP === false) {
            throw new \Exception("Invalid IPv4 address format: {$ip}");
        }

        // Append the binary IPv4 address directly
        $result .= $binaryIP;

        return $result;
    }

    protected function encodeIPv6(string $ip, int $ttl): string
    {
        $result = \pack('Nn', $ttl, 16);

        $binaryIP = inet_pton($ip);
        if ($binaryIP === false) {
            throw new \Exception("Invalid IPv6 address format: {$ip}");
        }

        $result .= $binaryIP;

        return $result;
    }

    protected function encodeDomain(string $domain, int $ttl): string
    {
        $result = '';
        $totalLength = 0;

        foreach (\explode('.', $domain) as $label) {
            $labelLength = \strlen($label);
            $result .= \chr($labelLength);
            $result .= $label;
            $totalLength += 1 + $labelLength;
        }

        $result .= \chr(0);
        $totalLength += 1;

        $result = \pack('Nn', $ttl, $totalLength) . $result;

        return $result;
    }

    protected function encodeText(string $text, int $ttl): string
    {
        $textLength = \strlen($text);
        $result = \pack('Nn', $ttl, 1 + $textLength) . \chr($textLength) . $text;

        return $result;
    }

    protected function encodeMx(string $domain, int $ttl, int $priority): string
    {
        $result = \pack('n', $priority);
        $totalLength = 2;

        foreach (\explode('.', $domain) as $label) {
            $labelLength = \strlen($label);
            $result .= \chr($labelLength);
            $result .= $label;
            $totalLength += 1 + $labelLength;
        }

        $result .= \chr(0);
        $totalLength += 1;

        $result = \pack('Nn', $ttl, $totalLength) . $result;

        return $result;
    }

    protected function encodeSrv(string $domain, int $ttl, int $priority, int $weight, int $port): string
    {
        $result = \pack('nnn', $priority, $weight, $port);
        $totalLength = 6;

        foreach (\explode('.', $domain) as $label) {
            $labelLength = \strlen($label);
            $result .= \chr($labelLength);
            $result .= $label;
            $totalLength += 1 + $labelLength;
        }

        $result .= \chr(0);
        $totalLength += 1;

        $result = \pack('Nn', $ttl, $totalLength) . $result;

        return $result;
    }

    /**
     * Encode a CAA record according to RFC 6844.
     *
     * @param array{flags?:int,tag?:string,value?:string}|string $rdata
     * @param int $ttl
     * @return string
     */
    protected function encodeCAA(array|string $rdata, int $ttl): string
    {
        $flags = 0;
        $tag = '';
        $value = '';
        if (is_array($rdata)) {
            $flags = isset($rdata['flags']) ? (int)$rdata['flags'] : 0;
            $tag = (string)($rdata['tag'] ?? 'issue');
            $value = (string)($rdata['value'] ?? '');
        } elseif (is_string($rdata)) {
            // Parse: 'flags tag "value"' or 'tag "value"' or 'flags tag value' or 'tag value'
            if (preg_match('/^(?:(\d+)\s+)?([a-zA-Z0-9_-]+)\s+"([^"]+)"$/', $rdata, $m)) {
                $flags = isset($m[1]) ? (int)$m[1] : 0;
                $tag = $m[2];
                $value = $m[3];
            } elseif (preg_match('/^(?:(\d+)\s+)?([a-zA-Z0-9_-]+)\s+(.+)$/', $rdata, $m)) {
                $flags = isset($m[1]) ? (int)$m[1] : 0;
                $tag = $m[2];
                $value = $m[3];
            } else {
                // fallback: treat all as issue value
                $tag = 'issue';
                $value = $rdata;
            }
        }
        // Validate flags (must be 0-255)
        $flags = max(0, min(255, $flags));
        $tagLen = strlen($tag);
        $valueLen = strlen($value);
        $rdataBin = chr($flags) . chr($tagLen) . $tag . $value;
        $totalLen = 2 + $tagLen + $valueLen;
        return pack('Nn', $ttl, $totalLen) . $rdataBin;
    }

    /**
     * Categorize error messages into standardized error types
     * to prevent high cardinality in telemetry metrics
     *
     * @param string $errorMessage
     * @return string
     */
    protected function categorizeError(string $errorMessage): string
    {
        return match (true) {
            str_contains($errorMessage, 'Out of memory') => 'memory_limit',
            str_contains($errorMessage, 'Maximum execution time') => 'timeout',
            str_contains($errorMessage, 'file_get_contents') ||
            str_contains($errorMessage, 'fopen') ||
            str_contains($errorMessage, 'Permission denied') => 'file_access',
            str_contains($errorMessage, 'Connection refused') ||
            str_contains($errorMessage, 'Connection timed out') => 'connection',
            str_contains($errorMessage, 'Undefined') => 'undefined_reference',
            str_contains($errorMessage, 'Invalid argument') => 'invalid_argument',
            str_contains($errorMessage, 'Cannot unpack') ||
            str_contains($errorMessage, 'Malformed') => 'malformed_packet',
            str_contains($errorMessage, 'Domain not found') ||
            str_contains($errorMessage, 'Host not found') => 'dns_resolution',
            default => 'other'
        };
    }
}
