<?php

namespace Utopia\DNS\Message;

final class Record
{
    public const int TYPE_A = 1;
    public const int TYPE_NS = 2;
    public const int TYPE_MD = 3;
    public const int TYPE_MF = 4;
    public const int TYPE_CNAME = 5;
    public const int TYPE_SOA = 6;
    public const int TYPE_MB = 7;
    public const int TYPE_MG = 8;
    public const int TYPE_MR = 9;
    public const int TYPE_NULL = 10;
    public const int TYPE_WKS = 11;
    public const int TYPE_PTR = 12;
    public const int TYPE_HINFO = 13;
    public const int TYPE_MINFO = 14;
    public const int TYPE_MX = 15;
    public const int TYPE_TXT = 16;
    public const int TYPE_AAAA = 28;
    public const int TYPE_SRV = 33;
    public const int TYPE_CAA = 257;

    public const int CLASS_IN = 1;
    public const int CLASS_CS = 2;
    public const int CLASS_CH = 3;
    public const int CLASS_HS = 4;

    private const int IPV4_LEN = 4;
    private const int IPV6_LEN = 16;
    private const int MAX_PRIORITY = 65535;
    private const int MAX_WEIGHT = 65535;
    private const int MAX_PORT = 65535;
    private const int MAX_CAA_FLAGS = 255;
    private const int MAX_TXT_CHUNK = 255;

    /**
     * Map between textual record mnemonics and their numeric codes.
     *
     * @var array<string, int>
     */
    private const array TYPE_NAME_TO_CODE = [
        'A' => self::TYPE_A,
        'NS' => self::TYPE_NS,
        'MD' => self::TYPE_MD,
        'MF' => self::TYPE_MF,
        'CNAME' => self::TYPE_CNAME,
        'SOA' => self::TYPE_SOA,
        'MB' => self::TYPE_MB,
        'MG' => self::TYPE_MG,
        'MR' => self::TYPE_MR,
        'NULL' => self::TYPE_NULL,
        'WKS' => self::TYPE_WKS,
        'PTR' => self::TYPE_PTR,
        'HINFO' => self::TYPE_HINFO,
        'MINFO' => self::TYPE_MINFO,
        'MX' => self::TYPE_MX,
        'TXT' => self::TYPE_TXT,
        'AAAA' => self::TYPE_AAAA,
        'SRV' => self::TYPE_SRV,
        'CAA' => self::TYPE_CAA,
    ];

    /**
     * Reverse map between numeric codes and record mnemonics.
     *
     * @var array<int, string>
     */
    private const array TYPE_CODE_TO_NAME = [
        self::TYPE_A => 'A',
        self::TYPE_NS => 'NS',
        self::TYPE_MD => 'MD',
        self::TYPE_MF => 'MF',
        self::TYPE_CNAME => 'CNAME',
        self::TYPE_SOA => 'SOA',
        self::TYPE_MB => 'MB',
        self::TYPE_MG => 'MG',
        self::TYPE_MR => 'MR',
        self::TYPE_NULL => 'NULL',
        self::TYPE_WKS => 'WKS',
        self::TYPE_PTR => 'PTR',
        self::TYPE_HINFO => 'HINFO',
        self::TYPE_MINFO => 'MINFO',
        self::TYPE_MX => 'MX',
        self::TYPE_TXT => 'TXT',
        self::TYPE_AAAA => 'AAAA',
        self::TYPE_SRV => 'SRV',
        self::TYPE_CAA => 'CAA',
    ];

    public function __construct(
        public readonly string $name,
        public readonly int $type,
        public readonly int $class = Record::CLASS_IN,
        public readonly int $ttl = 0,
        public readonly string $rdata = '',
        public readonly ?int $priority = null,
        public readonly ?int $weight = null,
        public readonly ?int $port = null
    ) {
    }

    /**
     * Parse a DNS Resource Record from raw binary data.
     *
     * @param string $data   Full DNS packet data
     * @param int    &$offset Offset to start reading (updated after)
     * @return self
     */
    /**
     * @param-out int $offset
     */
    public static function decode(string $data, int &$offset): self
    {
        // 1. Parse NAME (may use compression)
        $name = self::decodeName($data, $offset);

        // 2. Read fixed-length fields
        $limit = strlen($data);
        if ($offset + 10 > $limit) {
            throw new \InvalidArgumentException('Truncated RR header');
        }
        $typeData = unpack('ntype', substr($data, $offset, 2));
        if (!is_array($typeData) || !array_key_exists('type', $typeData)) {
            throw new \InvalidArgumentException('Failed to unpack record type');
        }
        $type = $typeData['type'];
        $offset += 2;

        $classData = unpack('nclass', substr($data, $offset, 2));
        if (!is_array($classData) || !array_key_exists('class', $classData)) {
            throw new \InvalidArgumentException('Failed to unpack record class');
        }
        $class = $classData['class'];
        $offset += 2;

        $ttlData = unpack('Nttl', substr($data, $offset, 4));
        if (!is_array($ttlData) || !array_key_exists('ttl', $ttlData)) {
            throw new \InvalidArgumentException('Failed to unpack record TTL');
        }
        $ttl = $ttlData['ttl'];
        $offset += 4;

        $rdLengthData = unpack('nlength', substr($data, $offset, 2));
        if (!is_array($rdLengthData) || !array_key_exists('length', $rdLengthData)) {
            throw new \InvalidArgumentException('Failed to unpack record length');
        }
        $rdlength = $rdLengthData['length'];
        $offset += 2;

        if ($offset + $rdlength > $limit) {
            throw new \InvalidArgumentException('RDATA exceeds packet bounds');
        }
        $rdataRaw = substr($data, $offset, $rdlength);
        $offset = (int) ($offset + $rdlength);

        // 3. Interpret RDATA based on type
        $rdata = '';
        $priority = $weight = $port = null;

        switch ($type) {
            case Record::TYPE_A:
                if (strlen($rdataRaw) !== Record::IPV4_LEN) {
                    throw new \InvalidArgumentException('Invalid IPv4 address length');
                }
                $decoded = inet_ntop($rdataRaw);
                if ($decoded === false) {
                    throw new \InvalidArgumentException('Invalid IPv4 address payload');
                }
                $rdata = $decoded;
                break;

            case Record::TYPE_AAAA:
                if (strlen($rdataRaw) !== Record::IPV6_LEN) {
                    throw new \InvalidArgumentException('Invalid IPv6 address length');
                }
                $decoded = inet_ntop($rdataRaw);
                if ($decoded === false) {
                    throw new \InvalidArgumentException('Invalid IPv6 address payload');
                }
                $rdata = $decoded;
                break;

            case Record::TYPE_CNAME:
            case Record::TYPE_NS:
            case Record::TYPE_PTR:
                $tempOffset = (int) ($offset - $rdlength);
                $rdata = self::decodeName($data, $tempOffset);
                break;

            case Record::TYPE_MX:
                if (strlen($rdataRaw) < 3) { // 2 bytes preference + at least 1 for name
                    throw new \InvalidArgumentException('Invalid MX RDATA length: ' . strlen($rdataRaw));
                }
                $priorityData = unpack('npriority', substr($rdataRaw, 0, 2));
                if (!is_array($priorityData) || !array_key_exists('priority', $priorityData)) {
                    throw new \InvalidArgumentException('Failed to unpack MX priority');
                }
                $priority = $priorityData['priority'];
                $tempOffset = (int) ($offset - $rdlength + 2);
                $rdata = self::decodeName($data, $tempOffset);
                break;

            case Record::TYPE_SRV:
                if (strlen($rdataRaw) < 7) { // 6 bytes (pri,weight,port) + at least 1 for name
                    throw new \InvalidArgumentException('Invalid SRV RDATA length: ' . strlen($rdataRaw));
                }
                $priorityData = unpack('npriority', substr($rdataRaw, 0, 2));
                $weightData = unpack('nweight', substr($rdataRaw, 2, 2));
                $portData = unpack('nport', substr($rdataRaw, 4, 2));
                if (!is_array($priorityData) || !array_key_exists('priority', $priorityData)) {
                    throw new \InvalidArgumentException('Failed to unpack SRV priority');
                }
                if (!is_array($weightData) || !array_key_exists('weight', $weightData)) {
                    throw new \InvalidArgumentException('Failed to unpack SRV weight');
                }
                if (!is_array($portData) || !array_key_exists('port', $portData)) {
                    throw new \InvalidArgumentException('Failed to unpack SRV port');
                }
                $priority = $priorityData['priority'];
                $weight = $weightData['weight'];
                $port = $portData['port'];
                $tempOffset = (int) ($offset - $rdlength + 6);
                $rdata = self::decodeName($data, $tempOffset);
                break;

            case Record::TYPE_SOA:
                $tempOffset = (int) ($offset - $rdlength);
                $mname = self::decodeName($data, $tempOffset);
                $rname = self::decodeName($data, $tempOffset);

                if ($mname !== '') {
                    $mname .= '.';
                }
                if ($rname !== '') {
                    $rname .= '.';
                }
                $timingData = substr($data, $tempOffset, 20);
                if (strlen($timingData) < 20) {
                    throw new \InvalidArgumentException('Invalid SOA record length');
                }

                $fields = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminimum', $timingData);
                if (!is_array($fields)) {
                    throw new \InvalidArgumentException('Unable to unpack SOA timings');
                }

                $rdata = sprintf(
                    '%s %s %u %u %u %u %u',
                    $mname,
                    $rname,
                    $fields['serial'],
                    $fields['refresh'],
                    $fields['retry'],
                    $fields['expire'],
                    $fields['minimum']
                );
                break;

            case Record::TYPE_TXT:
                if ($rdlength < 1) {
                    throw new \InvalidArgumentException('Invalid TXT RDATA length: 0');
                }
                $len = ord($rdataRaw[0]);
                if ($len > $rdlength - 1) {
                    throw new \InvalidArgumentException('TXT length octet exceeds RDATA size');
                }
                $rdata = substr($rdataRaw, 1, $len);
                break;

            case Record::TYPE_CAA:
                if ($rdlength < 2) {
                    throw new \InvalidArgumentException('Invalid CAA record length');
                }

                $flags = ord($rdataRaw[0]);
                $tagLength = ord($rdataRaw[1]);
                if ($tagLength > strlen($rdataRaw) - 2) {
                    throw new \InvalidArgumentException('Invalid CAA tag length');
                }

                $tag = substr($rdataRaw, 2, $tagLength);
                $value = substr($rdataRaw, 2 + $tagLength);
                $rdata = sprintf('%d %s "%s"', $flags, $tag, $value);
                break;

            default:
                $rdata = bin2hex($rdataRaw);
                break;
        }

        return new self($name, $type, $class, $ttl, $rdata, $priority, $weight, $port);
    }

    public static function typeNameToCode(string $name): ?int
    {
        return self::TYPE_NAME_TO_CODE[strtoupper($name)] ?? null;
    }

    public static function typeCodeToName(int $code): ?string
    {
        return self::TYPE_CODE_TO_NAME[$code] ?? null;
    }

    /**
     * Parse a domain name from the packet, handling compression.
     */
    /**
     * @param-out int $offset
     */
    private static function decodeName(string $data, int &$offset): string
    {
        $labels = [];
        $jumped = false;
        $pos = $offset;
        $dataLength = strlen($data);
        $loopGuard = 0;

        while (true) {
            if ($loopGuard++ > $dataLength) {
                throw new \InvalidArgumentException('Possible compression pointer loop while decoding domain name');
            }

            if ($pos >= $dataLength) {
                throw new \InvalidArgumentException('Unexpected end of data while decoding domain name');
            }

            $len = ord($data[$pos]);
            if ($len === 0) {
                if (!$jumped) {
                    $offset = $pos + 1;
                }
                break;
            }

            // Handle compression pointer (0xC0)
            if (($len & 0xC0) === 0xC0) {
                if ($pos + 1 >= $dataLength) {
                    throw new \InvalidArgumentException('Truncated compression pointer in domain name');
                }

                $pointer = (($len & 0x3F) << 8) | ord($data[$pos + 1]);
                if ($pointer >= $dataLength) {
                    throw new \InvalidArgumentException('Compression pointer out of bounds in domain name');
                }
                if (!$jumped) {
                    $offset = $pos + 2;
                }
                $pos = $pointer;
                $jumped = true;
                continue;
            }

            if ($pos + 1 + $len > $dataLength) {
                throw new \InvalidArgumentException('Label length exceeds remaining data while decoding domain name');
            }

            $labels[] = substr($data, $pos + 1, $len);
            $pos += $len + 1;

            if (!$jumped) {
                $offset = $pos;
            }
        }

        return implode('.', $labels);
    }

    /**
     * Encode this record into DNS packet format.
     *
     * @param string $packet Full DNS packet (for compression pointer calculations)
     * @return string Binary representation of the record
     */
    public function encode(string $packet = ''): string
    {
        $data = '';

        // 1. Encode NAME
        $data .= Domain::encode($this->name);

        // 2. TYPE (2 bytes)
        $data .= pack('n', $this->type);

        // 3. CLASS (2 bytes)
        $data .= pack('n', $this->class);

        // 4. TTL (4 bytes)
        $data .= pack('N', $this->ttl);

        // 5. RDLENGTH + RDATA
        $rdata = $this->encodeRdata($packet . $data);
        $data .= pack('n', strlen($rdata));
        $data .= $rdata;

        return $data;
    }

    /**
     * Encode RDATA based on record type.
     */
    private function encodeRdata(string $packet): string
    {
        switch ($this->type) {
            case self::TYPE_A:
                $packed = inet_pton($this->rdata);
                if ($packed === false || strlen($packed) !== self::IPV4_LEN) {
                    throw new \InvalidArgumentException("Invalid IPv4 address: {$this->rdata}");
                }

                return $packed;

            case self::TYPE_AAAA:
                $packed = inet_pton($this->rdata);
                if ($packed === false || strlen($packed) !== self::IPV6_LEN) {
                    throw new \InvalidArgumentException("Invalid IPv6 address: {$this->rdata}");
                }

                return $packed;

            case self::TYPE_CNAME:
            case self::TYPE_NS:
            case self::TYPE_PTR:
                return Domain::encode($this->rdata);

            case self::TYPE_MX:
                $priority = $this->priority ?? 0;
                if ($priority < 0 || $priority > self::MAX_PRIORITY) {
                    throw new \InvalidArgumentException(
                        sprintf('MX priority must be between 0 and %d, got %d', self::MAX_PRIORITY, $priority)
                    );
                }

                return pack('n', $priority) . Domain::encode($this->rdata);

            case self::TYPE_SRV:
                $priority = $this->priority ?? 0;
                $weight = $this->weight ?? 0;
                $port = $this->port ?? 0;

                if ($priority < 0 || $priority > self::MAX_PRIORITY) {
                    throw new \InvalidArgumentException(
                        sprintf('SRV priority must be between 0 and %d, got %d', self::MAX_PRIORITY, $priority)
                    );
                }
                if ($weight < 0 || $weight > self::MAX_WEIGHT) {
                    throw new \InvalidArgumentException(
                        sprintf('SRV weight must be between 0 and %d, got %d', self::MAX_WEIGHT, $weight)
                    );
                }
                if ($port < 0 || $port > self::MAX_PORT) {
                    throw new \InvalidArgumentException(
                        sprintf('SRV port must be between 0 and %d, got %d', self::MAX_PORT, $port)
                    );
                }

                return pack('nnn', $priority, $weight, $port) .
                       Domain::encode($this->rdata);

            case self::TYPE_TXT:
                $len = strlen($this->rdata);
                if ($len > self::MAX_TXT_CHUNK) {
                    throw new \InvalidArgumentException(
                        'TXT record chunk exceeds ' . self::MAX_TXT_CHUNK . ' bytes'
                    );
                }

                return chr($len) . $this->rdata;

            case self::TYPE_CAA:
                return $this->encodeCaaRdata();

            case self::TYPE_SOA:
                return $this->encodeSoaRdata();

            default:
                // Assume hex-encoded for unknown types
                $binary = hex2bin($this->rdata);
                if ($binary === false) {
                    throw new \InvalidArgumentException('Invalid hexadecimal payload for record type ' . $this->type);
                }

                return $binary;
        }
    }

    private function encodeSoaRdata(): string
    {
        $input = trim($this->rdata);
        if ($input === '') {
            throw new \InvalidArgumentException('SOA RDATA cannot be empty');
        }

        $tokens = preg_split('/\s+/', $input);
        if ($tokens === false) {
            throw new \InvalidArgumentException('Unable to parse SOA RDATA');
        }

        $parts = [];
        foreach ($tokens as $token) {
            $clean = trim($token);
            if ($clean === '' || $clean === '(' || $clean === ')') {
                continue;
            }
            $parts[] = $clean;
        }

        if (count($parts) !== 7) {
            throw new \InvalidArgumentException(
                'SOA RDATA must contain MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE and MINIMUM fields'
            );
        }

        [$mname, $rname, $serial, $refresh, $retry, $expire, $minimum] = $parts;

        $numbers = [];
        foreach ([$serial, $refresh, $retry, $expire, $minimum] as $value) {
            if (!preg_match('/^\d+$/', $value)) {
                throw new \InvalidArgumentException('SOA timing fields must be unsigned integers');
            }

            $number = (int) $value;
            if ($number < 0 || $number > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('SOA timing field out of range: ' . $value);
            }
            $numbers[] = $number;
        }

        [$serialNum, $refreshNum, $retryNum, $expireNum, $minimumNum] = $numbers;

        return Domain::encode($mname)
            . Domain::encode($rname)
            . pack('NNNNN', $serialNum, $refreshNum, $retryNum, $expireNum, $minimumNum);
    }

    private function encodeCaaRdata(): string
    {
        $input = trim($this->rdata);
        if ($input === '') {
            throw new \InvalidArgumentException('CAA RDATA cannot be empty');
        }

        $pattern = '/^(?:(\d+)\s+)?([A-Za-z0-9-]+)\s+"((?:\\\\.|[^"])*)"$/';
        if (!preg_match($pattern, $input, $matches)) {
            throw new \InvalidArgumentException('Invalid CAA RDATA format: ' . $this->rdata);
        }

        $flags = (int) $matches[1];
        if ($flags < 0 || $flags > self::MAX_CAA_FLAGS) {
            throw new \InvalidArgumentException(
                sprintf('CAA flags must be between 0 and %d, got %d', self::MAX_CAA_FLAGS, $flags)
            );
        }

        $tag = $matches[2];
        if (strlen($tag) > 255) {
            throw new \InvalidArgumentException('CAA tag exceeds 255 bytes');
        }

        $value = stripcslashes($matches[3]);

        return chr($flags) . chr(strlen($tag)) . $tag . $value;
    }
}
