<?php

namespace Utopia\DNS\Validator;

use Utopia\DNS\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;
use Utopia\Domains\Domain;
use Utopia\Validator;

class DNS extends Validator
{
    public const RECORD_A = 'A';
    public const RECORD_AAAA = 'AAAA';
    public const RECORD_CNAME = 'CNAME';
    public const RECORD_CAA = 'CAA'; // You can provide domain only (as $target) for CAA validation

    protected const FAILURE_REASON_QUERY = 'DNS query failed.';
    protected const FAILURE_REASON_INTERNAL = 'Internal error occurred.';
    protected const FAILURE_REASON_UNKNOWN = '';
    protected const DEFAULT_DNS_SERVER = '8.8.8.8';

    /**
     * @var mixed
     */
    protected mixed $logs = [];

    public string $domain = '';
    public string $resolver = '';
    /**
     * @var array<string>
     */
    public array $recordValues = [];
    public int $count = 0;
    public string $reason = '';

    /**
     * @param string $target
     */
    public function __construct(protected string $target, protected string $type = self::RECORD_CNAME, string $dnsServer = '')
    {
        if (empty($dnsServer)) {
            $dnsServer = self::DEFAULT_DNS_SERVER;
        }

        $this->resolver = $dnsServer;
    }

    /**
     * @return string
     */
    public function getDescription(): string
    {
        if (!empty($this->reason)) {
            return $this->reason;
        }

        $messages = [];

        $messages[] = "DNS verification failed with resolver {$this->resolver}";

        if ($this->count === 0) {
            $messages[] = 'Domain ' . $this->domain . ' is missing ' . $this->type . ' record';
            return implode('. ', $messages) . '.';
        }

        $recordValuesVerbose = implode("', '", $this->recordValues);

        $countVerbose = match($this->count) {
            1 => 'one',
            2 => 'two',
            3 => 'three',
            4 => 'four',
            5 => 'five',
            6 => 'six',
            7 => 'seven',
            8 => 'eight',
            9 => 'nine',
            10 => 'ten',
            default => $this->count
        };

        if ($this->count === 1) {
            $messages[] = "Domain {$this->domain} has incorrect {$this->type} value '{$recordValuesVerbose}'";
        } else {
            // Two or more
            $messages[] = "Domain {$this->domain} has {$countVerbose} incompatible {$this->type} records: '{$recordValuesVerbose}'";
        }

        if ($this->type === self::RECORD_CAA) {
            $messages[] = 'Add new CAA record, or remove all other CAA records';
        }

        return implode('. ', $messages) . '.';
    }

    /**
     * @return mixed
     */
    public function getLogs(): mixed
    {
        return $this->logs;
    }

    /**
     * Check if DNS record value matches specific value
     *
     * @param mixed $value
     * @return bool
     */
    public function isValid(mixed $value): bool
    {
        return $this->isValidWithDNSServer($value, $this->resolver);
    }

    /**
     * Check if DNS record value matches specific value on a specific DNS server
     *
     * @param mixed $value
     * @param string $dnsServer
     * @return bool
     */
    public function isValidWithDNSServer(mixed $value, string $dnsServer): bool
    {
        if (!\is_string($value)) {
            $this->reason = self::FAILURE_REASON_INTERNAL;
            return false;
        }

        $this->count = 0;
        $this->domain = \strval($value);
        $this->reason = self::FAILURE_REASON_UNKNOWN;
        $this->recordValues = [];
        $this->resolver = $dnsServer;

        $dns = new Client($dnsServer);

        try {
            $typeCode = Record::typeNameToCode($this->type);
            if ($typeCode === null) {
                $this->reason = self::FAILURE_REASON_INTERNAL;
                return false;
            }
            $question = new Question($value, $typeCode);
            $queryMessage = Message::query($question, recursionDesired: true);
            $response = $dns->query($queryMessage);
            $rawQuery = $response->answers;
            var_dump($rawQuery);

            // Some DNS servers return all records, not only type that's asked for
            // Likely occurs when no records of specific type are found
            $query = array_filter($rawQuery, function ($record) {
                $typeName = Record::typeCodeToName($record->type);
                return $typeName === $this->type;
            });

            $this->logs = $query;
        } catch (\Exception $e) {
            var_dump("error in isValidWithDNSServer");
            $this->reason = self::FAILURE_REASON_QUERY;
            $this->logs = ['error' => $e->getMessage()];
            return false;
        }

        $this->count = \count($query);

        if (empty($query)) {
            // CAA records inherit from parent (custom CAA behaviour)
            if ($this->type === self::RECORD_CAA) {
                $domain = new Domain($value);
                if ($domain->get() === $domain->getApex()) {
                    return true; // No CAA on apex domain means anyone can issue certificate
                }

                // Recursive validation by parent domain
                $parts = \explode('.', $value);
                \array_shift($parts);
                $parentDomain = \implode('.', $parts);
                $validator = new self($this->target, DNS::RECORD_CAA, $dnsServer);
                return $validator->isValidWithDNSServer($parentDomain, $dnsServer);
            }

            return false;
        }

        foreach ($query as $record) {
            // CAA validation only needs to ensure domain
            if ($this->type === self::RECORD_CAA) {
                // Extract domain; comments showcase extraction steps in most complex scenario
                $rdata = $record->rdata; // 255 issuewild "certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600"
                $rdata = \explode(' ', $rdata, 3)[2] ?? ''; // "certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600"
                $rdata = \trim($rdata, '"'); // certainly.com;validationmethods=tls-alpn-01;retrytimeout=3600
                $rdata = \explode(';', $rdata, 2)[0]; // certainly.com

                $this->recordValues[] = $rdata;
                if ($rdata === $this->target) {
                    return true;
                }
            } else {
                $this->recordValues[] = $record->rdata;
            }

            if ($record->rdata === $this->target) {
                return true;
            }
        }

        return false;
    }

    /**
     * Is array
     *
     * Function will return true if object is array.
     *
     * @return bool
     */
    public function isArray(): bool
    {
        return false;
    }

    /**
     * Get Type
     *
     * Returns validator type.
     *
     * @return string
     */
    public function getType(): string
    {
        return self::TYPE_STRING;
    }
}
