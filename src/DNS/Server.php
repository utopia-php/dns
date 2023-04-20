<?php

namespace Utopia\DNS;

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

    public function __construct(Adapter $adapter, Resolver $resolver)
    {
        $this->adapter = $adapter;
        $this->resolver = $resolver;
    }

    public function start(): void
    {
        $this->adapter->onPacket(function (string $buffer, string $ip, int $port) {
            // Parse question domain
            $domain = "";
            $offset = 12;
            while ($offset < \strlen($buffer)) {
                // Get label length
                $labelLength = \ord($buffer[$offset]);

                // End of question
                if ($labelLength === 0 && \ord($buffer[$offset + 1]) === 0) {
                    // Skip over padding bytes
                    $offset += 1;
                    break;
                }

                // Extract label as string
                $label = \substr($buffer, $offset + 1, $labelLength);

                if (empty($domain)) {
                    $domain .= $label;
                } else {
                    $domain .= '.' . $label;
                }

                // Skip to next label length
                $offset += 1 + $labelLength;
            }

            // Parse question type
            $unpacked = \unpack('ntype/nclass', \substr($buffer, $offset, 4));
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
                'domain' => $domain,
                'type' => $type
            ];

            $answers = $this->resolve($question);

            // Build response
            $response = '';

            // Copy some of header
            $response .= \substr($buffer, 0, 6);

            // Add rest of header
            $response .= \pack(
                'nnn',
                \count($answers), // numberOfAnswers
                0, // numberOfAuthorities
                0, // numberOfAdditionals
            );

            // Copy questions section
            $response .= \substr($buffer, 12, $offset - 12);

            // Add answers section
            foreach ($answers as $answer) {
                $response .= \chr(192) . \chr(12); // 192 indicates this is pointer, 12 is offset to question.
                $response .= \pack('nn', $typeByte, $classByte);

                $answer['value'] = $answer['value'] ?? '';
                $answer['ttl'] = $answer['ttl'] ?? 1800;

                /**
                 * @var string $type
                 */
                $type = $question['type'];

                $response .= match ($type) {
                    'A' => $this->encodeIp($answer['value'], $answer['ttl']),
                    'AAAA' => $this->encodeIpv6($answer['value'], $answer['ttl']),
                    'CNAME' => $this->encodeDomain($answer['value'], $answer['ttl']),
                    'NS' => $this->encodeDomain($answer['value'], $answer['ttl']),
                    'TXT' => $this->encodeText($answer['value'], $answer['ttl']),
                    'CAA' => $this->encodeText($answer['value'], $answer['ttl']),
                    'MX' => $this->encodeMx($answer['value'], $answer['ttl'], $answer['priority']),
                    'SRV' => $this->encodeSrv($answer['value'], $answer['ttl'], $answer['priority'], $answer['weight'], $answer['port']),
                    default => ''
                };
            }

            return $response;
        });

        $this->adapter->start();
    }

    /**
     * Resolve domain name to IP by record type
     *
     * @param array<string, string> $question
     * @return array<array<string, mixed>>
     */
    protected function resolve(array $question): array
    {
        return $this->resolver->resolve($question);
    }

    protected function encodeIp(string $ip, int $ttl): string
    {
        $result = \pack('Nn', $ttl, 4);

        foreach (\explode('.', $ip) as $label) {
            $result .= \chr((int) $label);
        }

        return $result;
    }

    protected function encodeIpv6(string $ip, int $ttl): string
    {
        $result = \pack('Nn', $ttl, 16);

        foreach (\explode(':', $ip) as $label) {
            $result .= \pack('n', \hexdec($label));
        }

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
}
