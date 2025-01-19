<?php

namespace Utopia\DNS;

class Client
{
    /** @var string */
    private $server;

    /** @var int */
    private $port;

    /**
     * Mapping of record type names to their numeric codes.
     *
     * @var array
     */
    private $recordTypes = [
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
    ];

    /**
     * Client constructor.
     *
     * @param string $server DNS server IP or hostname.
     * @param int    $port   DNS server port (default is 53).
     */
    public function __construct(string $server, int $port = 53)
    {
        $this->server = $server;
        $this->port   = $port;
    }

    /**
     * Query the DNS server for a given domain and record type.
     *
     * @param string $domain Domain to query.
     * @param string $type   DNS record type (e.g., A, MX, TXT).
     * @return Record[]    Array of Record objects.
     * @throws \Exception  On query errors.
     */
    public function query(string $domain, string $type = 'A'): array
    {
        $type = strtoupper($type);
        if (!isset($this->recordTypes[$type])) {
            throw new \Exception("Unknown record type: {$type}");
        }
        $qtype  = $this->recordTypes[$type];
        $packet = $this->buildDnsQueryPacket($domain, $qtype);

        // Create a UDP socket.
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$socket) {
            throw new \Exception("Unable to create socket.");
        }

        // Send the DNS query packet.
        if (!socket_sendto($socket, $packet, strlen($packet), 0, $this->server, $this->port)) {
            socket_close($socket);
            throw new \Exception("Failed to send data to DNS server {$this->server}:{$this->port}");
        }

        // Set a timeout for the response.
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);

        // Receive the response.
        $response = '';
        if (false === socket_recvfrom($socket, $response, 4096, 0, $this->server, $this->port)) {
            socket_close($socket);
            throw new \Exception("Failed to receive data from {$this->server}");
        }
        socket_close($socket);

        return $this->parseDnsResponse($response);
    }

    /**
     * Build a binary DNS query packet.
     *
     * @param string $domain Domain to query.
     * @param int    $qtype  Numeric query type.
     * @return string        DNS query packet.
     */
    private function buildDnsQueryPacket(string $domain, int $qtype): string
    {
        // Transaction ID: 2 bytes (random)
        $id = random_int(0, 0xffff);
        $header = pack('n', $id);
        // Flags: standard query with recursion desired (0x0100)
        $header .= pack('n', 0x0100);
        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0.
        $header .= pack('nnnn', 1, 0, 0, 0);

        // Build the question section (domain in DNS label format).
        $qname = '';
        foreach (explode('.', $domain) as $label) {
            $qname .= chr(strlen($label)) . $label;
        }
        $qname .= "\0";  // End of domain name.

        // QTYPE and QCLASS (IN = 1).
        $question = $qname . pack('nn', $qtype, 1);

        return $header . $question;
    }

    /**
     * Parse a DNS response packet and extract answer records.
     *
     * @param string $packet The raw DNS response.
     * @return Record[]      Array of Record objects.
     */
    private function parseDnsResponse(string $packet): array
    {
        $records = [];
        if (strlen($packet) < 12) {
            return $records;
        }

        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', substr($packet, 0, 12));
        $offset = 12;

        // Skip the question section.
        for ($i = 0; $i < $header['qdcount']; $i++) {
            $this->decodeDomainName($packet, $offset);
            $offset += 4; // Skip QTYPE and QCLASS.
        }

        // Parse the answer records.
        for ($i = 0; $i < $header['ancount']; $i++) {
            $name = $this->decodeDomainName($packet, $offset);
            if (strlen($packet) < $offset + 10) {
                break;
            }
            $rr = unpack('ntype/nclass/Nttl/nrdlength', substr($packet, $offset, 10));
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

    /**
     * Decode a domain name from the DNS packet.
     *
     * Handles both traditional labels and compression pointers.
     *
     * @param string $packet  The full DNS packet.
     * @param int    &$offset Current offset (by reference).
     * @return string         Decoded domain name.
     */
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
            // Check for pointer (if the two highest bits are set).
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

    /**
     * Parse the RDATA field for a resource record.
     *
     * @param string $packet   The full DNS packet.
     * @param int    &$offset  Current offset for RDATA (by reference).
     * @param int    $type     Numeric record type.
     * @param int    $rdlength Length of RDATA.
     * @return string          Human‑readable record data.
     */
    private function parseRdata(string $packet, int &$offset, int $type, int $rdlength): string
    {
        switch ($type) {
            case 1: // A record
                $data = substr($packet, $offset, 4);
                $offset += 4;
                return inet_ntop($data);
            case 28: // AAAA record
                $data = substr($packet, $offset, 16);
                $offset += 16;
                return inet_ntop($data);
            case 2: // NS record
            case 5: // CNAME record
            case 12: // PTR record
                return $this->decodeDomainName($packet, $offset);
            case 15: // MX record
                $pref = unpack('n', substr($packet, $offset, 2))[1];
                $offset += 2;
                $exchange = $this->decodeDomainName($packet, $offset);
                return "Preference: {$pref}, Exchange: {$exchange}";
            case 16: // TXT record
                $txts = [];
                $end = $offset + $rdlength;
                while ($offset < $end) {
                    $len = ord($packet[$offset]);
                    $offset++;
                    $txts[] = substr($packet, $offset, $len);
                    $offset += $len;
                }
                return implode(' ', $txts);
            case 33: // SRV record
                $priority = unpack('n', substr($packet, $offset, 2))[1];
                $offset += 2;
                $weight = unpack('n', substr($packet, $offset, 2))[1];
                $offset += 2;
                $port = unpack('n', substr($packet, $offset, 2))[1];
                $offset += 2;
                $target = $this->decodeDomainName($packet, $offset);
                return "Priority: {$priority}, Weight: {$weight}, Port: {$port}, Target: {$target}";
            case 6: // SOA record
                $mname = $this->decodeDomainName($packet, $offset);
                $rname = $this->decodeDomainName($packet, $offset);
                $parts = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminttl', substr($packet, $offset, 20));
                $offset += 20;
                return "MNAME: {$mname}, RNAME: {$rname}, Serial: {$parts['serial']}, Refresh: {$parts['refresh']}, Retry: {$parts['retry']}, Expire: {$parts['expire']}, Minimum TTL: {$parts['minttl']}";
            default:
                // For unsupported types, return the raw data as a hex string.
                $data = substr($packet, $offset, $rdlength);
                $offset += $rdlength;
                return '0x' . bin2hex($data);
        }
    }
}
