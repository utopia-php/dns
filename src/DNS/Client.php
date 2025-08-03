<?php

namespace Utopia\DNS;

use Exception;

class Client
{
    /** @var \Socket */
    protected $socket;
    protected string $server;
    protected int $port;
    protected int $timeout;

    /**
     * Mapping of record type names to their numeric codes.
     *
     * @var array<string, int>
     */
    private array $recordTypes = [
        'A'     => 1,
        'NS'    => 2,
        'MD'    => 3,
        'MF'    => 4,
        'CNAME' => 5,
        'SOA'   => 6,
        'MB'    => 7,
        'MG'    => 8,
        'MR'    => 9,
        'NULL'  => 10,
        'WKS'   => 11,
        'PTR'   => 12,
        'HINFO' => 13,
        'MINFO' => 14,
        'MX'    => 15,
        'TXT'   => 16,
        'AAAA'  => 28,
        'SRV'   => 33,
        'CAA'   => 257,
    ];

    public function __construct(string $server = '127.0.0.1', int $port = 53, int $timeout = 5)
    {
        $this->server = $server;
        $this->port = $port;
        $this->timeout = $timeout;

        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

        if ($socket === false) {
            throw new Exception('Failed to create socket: ' . socket_strerror(socket_last_error()));
        }

        // Set socket timeout
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => $timeout, 'usec' => 0));
        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, array('sec' => $timeout, 'usec' => 0));

        $this->socket = $socket;
    }

    /**
     * @return array<int, \Utopia\DNS\Record>
     */
    public function query(string $domain, string $type = 'A'): array
    {
        try {
            $type = strtoupper($type);
            if (!isset($this->recordTypes[$type])) {
                throw new Exception("Unknown record type: {$type}");
            }
            $qtype  = $this->recordTypes[$type];
            $packet = $this->buildDnsQueryPacket($domain, $qtype);

            if (socket_sendto($this->socket, $packet, strlen($packet), 0, $this->server, $this->port) === false) {
                throw new Exception('Failed to send data: ' . socket_strerror(socket_last_error($this->socket)));
            }

            $response = '';
            $from = '';
            $port = 0;

            $result = socket_recvfrom($this->socket, $response, 512, 0, $from, $port);

            if ($result === false) {
                $error = socket_last_error($this->socket);
                $errorMessage = socket_strerror($error);
                throw new Exception("Failed to receive data from {$this->server}: {$errorMessage} (Error code: {$error})");
            }

            if (empty($response)) {
                throw new Exception("Empty response received from {$this->server}:{$this->port}");
            }

            return $this->parseDnsResponse($response);
        } catch (Exception $e) {
            throw new Exception($e->getMessage(), $e->getCode(), $e);
        }
    }

    private function buildDnsQueryPacket(string $domain, int $qtype): string
    {
        $id = random_int(0, 0xffff);
        $header = pack('n', $id);
        $header .= pack('n', 0x0100);
        $header .= pack('nnnn', 1, 0, 0, 0);

        $qname = '';
        foreach (explode('.', $domain) as $label) {
            $qname .= chr(strlen($label)) . $label;
        }
        $qname .= "\0";

        $question = $qname . pack('nn', $qtype, 1);

        return $header . $question;
    }

    /**
     * @return array<int, Record>
     */
    private function parseDnsResponse(string $packet): array
    {
        $records = [];
        if (strlen($packet) < 12) {
            return $records;
        }

        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', substr($packet, 0, 12));
        if ($header === false || !isset($header['qdcount'], $header['ancount'])) {
            throw new Exception("Invalid DNS header.");
        }

        $offset = 12;

        for ($i = 0; $i < $header['qdcount']; $i++) {
            $this->decodeDomainName($packet, $offset);
            $offset += 4;
        }

        for ($i = 0; $i < $header['ancount']; $i++) {
            $name = $this->decodeDomainName($packet, $offset);
            if (strlen($packet) < $offset + 10) {
                break;
            }
            $rr = unpack('ntype/nclass/Nttl/nrdlength', substr($packet, $offset, 10));
            if ($rr === false || !isset($rr['type'], $rr['class'], $rr['ttl'], $rr['rdlength'])) {
                throw new Exception("Invalid resource record format.");
            }
            $offset += 10;

            $rdata = $this->parseRdata($packet, $offset, $rr['type'], $rr['rdlength']);
            $record = new Record();
            $record->setName($name)
                   ->setType($rr['type'])
                   ->setClass($rr['class'])
                   ->setTTL($rr['ttl'])
                   ->setRdata($rdata);

            $records[] = $record;
        }
        return $records;
    }

    private function decodeDomainName(string $packet, int &$offset): string
    {
        $labels   = [];
        $jumped   = false;
        $original = $offset;

        while (true) {
            $length = ord($packet[$offset]);
            if ($length === 0) {
                $offset++;
                break;
            }
            if (($length & 0xC0) === 0xC0) {
                if (!$jumped) {
                    $original = $offset + 2;
                }
                $pointer = ((ord($packet[$offset]) & 0x3F) << 8) | ord($packet[$offset + 1]);
                $offset = $pointer;
                $jumped = true;
                continue;
            }
            $offset++;
            $labels[] = substr($packet, $offset, $length);
            $offset += $length;
        }
        if ($jumped) {
            $offset = $original;
        }
        return implode('.', $labels);
    }

    private function parseRdata(string $packet, int &$offset, int $type, int $rdlength): string
    {
        switch ($type) {
            case 1: // A record
                $data = substr($packet, $offset, 4);
                if ($data == '') {
                    throw new Exception("Failed to parse A record RDATA.");
                }
                $offset += 4;
                return inet_ntop($data) ?: throw new Exception("Failed to convert IP address");
            case 28: // AAAA record
                $data = substr($packet, $offset, 16);
                if ($data == '') {
                    throw new Exception("Failed to parse AAAA record RDATA.");
                }
                $offset += 16;
                return inet_ntop($data) ?: throw new Exception("Failed to convert IPv6 address");
            case 2: // NS record
            case 5: // CNAME record
            case 12: // PTR record
                return $this->decodeDomainName($packet, $offset);
            case 15: // MX record
                $pref = unpack('n', substr($packet, $offset, 2));
                if ($pref === false || !isset($pref[1])) {
                    throw new Exception("Failed to parse MX record preference.");
                }
                $offset += 2;
                $exchange = $this->decodeDomainName($packet, $offset);
                return "Preference: {$pref[1]}, Exchange: {$exchange}";
            case 16: // TXT record
                $txts = [];
                $end = $offset + $rdlength;
                while ($offset < $end) {
                    $len = ord($packet[$offset]);
                    $offset++;
                    $chunk = ($len > 0) ? substr($packet, $offset, $len) : '';
                    $txts[] = $chunk;
                    $offset += $len;
                }
                return implode('', $txts);
            case 33: // SRV record
                $priority = unpack('n', substr($packet, $offset, 2));
                $weight = unpack('n', substr($packet, $offset + 2, 2));
                $port = unpack('n', substr($packet, $offset + 4, 2));
                if ($priority === false || $weight === false || $port === false) {
                    throw new Exception("Failed to parse SRV record.");
                }
                $offset += 6;
                $target = $this->decodeDomainName($packet, $offset);
                return "Priority: {$priority[1]}, Weight: {$weight[1]}, Port: {$port[1]}, Target: {$target}";
            case 257: // CAA record
                if ($rdlength < 2) {
                    throw new Exception("CAA record too short (rdlength={$rdlength})");
                }
                $flags = ord($packet[$offset++]);
                $tagLength = ord($packet[$offset++]);
                $tag = substr($packet, $offset, $tagLength);
                $offset += $tagLength;
                $value = substr($packet, $offset, $rdlength - 2 - $tagLength);
                $offset += $rdlength - 2 - $tagLength;
                return "{$flags} {$tag} \"{$value}\"";
            case 6: // SOA record
                $mname = $this->decodeDomainName($packet, $offset);
                $rname = $this->decodeDomainName($packet, $offset);
                $parts = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminttl', substr($packet, $offset, 20));
                if ($parts === false || !isset($parts['serial'], $parts['refresh'], $parts['retry'], $parts['expire'], $parts['minttl'])) {
                    throw new Exception("Failed to parse SOA record.");
                }
                $offset += 20;
                return "MNAME: {$mname}, RNAME: {$rname}, Serial: {$parts['serial']}, Refresh: {$parts['refresh']}, Retry: {$parts['retry']}, Expire: {$parts['expire']}, Minimum TTL: {$parts['minttl']}";
            default:
                $data = substr($packet, $offset, $rdlength);
                if ($data == false) {
                    throw new Exception("Failed to parse unknown RDATA.");
                }
                $offset += $rdlength;
                return '0x' . bin2hex($data);
        }
    }
}
