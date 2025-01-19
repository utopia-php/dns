<?php

namespace Utopia\DNS;

class Record
{
    /**
     * @var string
     */
    private $name = '';

    /**
     * @var int
     */
    private $type = 0;

    /**
     * @var string
     */
    private $class = '';

    /**
     * @var int
     */
    private $ttl = 0;

    /**
     * @var string
     */
    private $rdata = '';

    // Optional fields, default to null.
    /**
     * @var int|null
     */
    private $priority = null;

    /**
     * @var int|null
     */
    private $weight = null;

    /**
     * @var int|null
     */
    private $port = null;

    /**
     * Record constructor.
     *
     * You may instantiate without parameters, then use setters, or pass initial values.
     *
     * @param string $name
     * @param int    $ttl
     * @param string $class
     * @param int|string $type
     * @param string $rdata
     */
    public function __construct(
        string $name = '',
        int $ttl = 0,
        string $class = 'IN',
        $type = 0,
        string $rdata = ''
    ) {
        $this->name  = $name;
        $this->ttl   = $ttl;
        $this->setClass($class);
        $this->setType($type);
        $this->rdata = $rdata;
    }

    /**
     * Get the domain name.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Set the domain name.
     *
     * @param string $name
     * @return Record
     */
    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    /**
     * Get the numeric record type.
     *
     * @return int
     */
    public function getType(): int
    {
        return $this->type;
    }

    /**
     * Set the record type.
     *
     * Accepts either a numeric code or a string representation.
     * If a string is provided, it will attempt to convert it to the correct numeric code.
     *
     * @param int|string $type
     * @return Record
     */
    public function setType($type): self
    {
        if (is_int($type)) {
            $this->type = $type;
        } elseif (is_string($type)) {
            // Map common record names to their numeric codes.
            $map = [
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
            $upper = strtoupper($type);
            $this->type = $map[$upper] ?? 0;
        }
        return $this;
    }

    /**
     * Get the DNS class.
     *
     * @return string
     */
    public function getClass(): string
    {
        $classes = [
            1 => 'IN',  // Internet
            2 => 'CS',  // CSNET
            3 => 'CH',  // CHAOS
            4 => 'HS',  // Hesiod
        ];
        return $classes[$this->class] ?? "CLASS{$this->class}";
    }

    /**
     * Set the DNS class.
     *
     * Accepts either a numeric code or a string representation.
     *
     * @param int|string $class
     * @return Record
     */
    public function setClass($class): self
    {
        if (is_int($class)) {
            $this->class = $class;
        } elseif (is_string($class)) {
            $map = [
                'IN' => 1,
                'CS' => 2,
                'CH' => 3,
                'HS' => 4,
            ];
            $upper = strtoupper($class);
            $this->class = $map[$upper] ?? 1; // Default to 'IN' if class is invalid
        }
        return $this;
    }

    /**
     * Get the TTL.
     *
     * @return int
     */
    public function getTTL(): int
    {
        return $this->ttl;
    }

    /**
     * Set the TTL.
     *
     * @param int $ttl
     * @return Record
     */
    public function setTTL(int $ttl): self
    {
        $this->ttl = $ttl;
        return $this;
    }

    /**
     * Get the rdata (record data).
     *
     * @return string
     */
    public function getRdata(): string
    {
        return $this->rdata;
    }

    /**
     * Set the rdata (record data).
     *
     * @param string $rdata
     * @return Record
     */
    public function setRdata(string $rdata): self
    {
        $this->rdata = $rdata;
        return $this;
    }

    /**
     * Get the priority (optional field).
     *
     * @return int|null
     */
    public function getPriority(): ?int
    {
        return $this->priority;
    }

    /**
     * Set the priority (optional field).
     *
     * @param int|null $priority
     * @return Record
     */
    public function setPriority(?int $priority): self
    {
        $this->priority = $priority;
        return $this;
    }

    /**
     * Get the weight (optional field).
     *
     * @return int|null
     */
    public function getWeight(): ?int
    {
        return $this->weight;
    }

    /**
     * Set the weight (optional field).
     *
     * @param int|null $weight
     * @return Record
     */
    public function setWeight(?int $weight): self
    {
        $this->weight = $weight;
        return $this;
    }

    /**
     * Get the port (optional field).
     *
     * @return int|null
     */
    public function getPort(): ?int
    {
        return $this->port;
    }

    /**
     * Set the port (optional field).
     *
     * @param int|null $port
     * @return Record
     */
    public function setPort(?int $port): self
    {
        $this->port = $port;
        return $this;
    }

    /**
     * Get the human‑readable type name.
     *
     * @return string
     */
    public function getTypeName(): string
    {
        $types = [
            1  => 'A',
            2  => 'NS',
            3  => 'MD',
            4  => 'MF',
            5  => 'CNAME',
            6  => 'SOA',
            7  => 'MB',
            8  => 'MG',
            9  => 'MR',
            10 => 'NULL',
            11 => 'WKS',
            12 => 'PTR',
            13 => 'HINFO',
            14 => 'MINFO',
            15 => 'MX',
            16 => 'TXT',
            28 => 'AAAA',
            33 => 'SRV',
        ];
        return $types[$this->type] ?? "TYPE{$this->type}";
    }

    /**
     * Return a human‑readable string representation of the record.
     *
     * @return string
     */
    public function __toString(): string
    {
        return sprintf(
            "Name: %s, Type: %s, TTL: %d, Data: %s",
            $this->name,
            $this->getTypeName(),
            $this->ttl,
            $this->rdata
        );
    }
}
