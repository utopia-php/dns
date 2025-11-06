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
    protected const FAILURE_REASON_QUERY = 'DNS query failed.';
    protected const FAILURE_REASON_INTERNAL = 'Internal error occurred.';
    protected const FAILURE_REASON_UNKNOWN = '';
    protected const DEFAULT_DNS_SERVER = '8.8.8.8';

    // Memory from isValid to be used in getDescription
    /**
     * @var mixed
     */
    protected mixed $logs = [];
    /**
     * @var array<string>
     */
    public array $recordValues = [];
    public string $domain = '';
    public int $count = 0;
    public string $reason = '';

    /**
     * @param string $target Expected value for the DNS record
     * @param int $type Type of DNS record to validate
     *  For value, use const from Record, such as Record::TYPE_A
     *  When using CAA type, you can provide exact match, or just issuer domain as $target
     * @param string $dnsServer DNS server IP or domain to use for validation
     */
    public function __construct(protected string $target, protected int $type = Record::TYPE_CNAME, protected string $dnsServer = self::DEFAULT_DNS_SERVER)
    {
    }

    /**
     * @return string
     */
    public function getDescription(): string
    {
        if (!empty($this->reason)) {
            return $this->reason;
        }

        $typeVerbose = Record::typeCodeToName($this->type) ?? $this->type;

        $messages = [];

        $messages[] = "DNS verification failed with resolver {$this->dnsServer}";

        if ($this->count === 0) {
            $messages[] = 'Domain ' . $this->domain . ' is missing ' . $typeVerbose . ' record';
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
            $messages[] = "Domain {$this->domain} has incorrect {$typeVerbose} value '{$recordValuesVerbose}'";
        } else {
            // Two or more
            $messages[] = "Domain {$this->domain} has {$countVerbose} incompatible {$typeVerbose} records: '{$recordValuesVerbose}'";
        }

        if ($this->type === Record::TYPE_CAA) {
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
        if (!\is_string($value)) {
            $this->reason = self::FAILURE_REASON_INTERNAL;
            return false;
        }

        $this->count = 0;
        $this->domain = \strval($value);
        $this->reason = self::FAILURE_REASON_UNKNOWN;
        $this->recordValues = [];

        $dns = new Client($this->dnsServer);

        try {
            $question = new Question($value, $this->type);
            $queryMessage = Message::query($question, recursionDesired: true);
            $response = $dns->query($queryMessage);
            $rawQuery = $response->answers;

            // Some DNS servers return all records, not only type that's asked for
            // Likely occurs when no records of specific type are found
            $query = array_filter($rawQuery, function ($record) {
                return $record->type === $this->type;
            });

            $this->logs = $query;
        } catch (\Exception $e) {
            $this->reason = self::FAILURE_REASON_QUERY;
            $this->logs = ['error' => $e->getMessage()];
            return false;
        }

        $this->count = \count($query);

        if (empty($query)) {
            // CAA records inherit from parent (custom CAA behaviour)
            if ($this->type === Record::TYPE_CAA) {
                $domain = new Domain($value);
                if ($domain->get() === $domain->getApex()) {
                    return true; // No CAA on apex domain means anyone can issue certificate
                }

                // Recursive validation by parent domain
                $parts = \explode('.', $value);
                \array_shift($parts);
                $parentDomain = \implode('.', $parts);
                $validator = new self($this->target, $this->type, $this->dnsServer);
                return $validator->isValid($parentDomain);
            }

            return false;
        }

        foreach ($query as $record) {
            // CAA validation only needs to ensure domain
            if ($this->type === Record::TYPE_CAA) {
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
