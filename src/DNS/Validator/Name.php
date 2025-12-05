<?php

namespace Utopia\DNS\Validator;

use Utopia\DNS\Message\Domain;
use Utopia\DNS\Message\Record;
use Utopia\Validator;

class Name extends Validator
{
    private const array RECORD_TYPES_WITH_UNDERSCORE_IN_NAME = [Record::TYPE_SRV, Record::TYPE_TXT];

    public const int LABEL_MAX_LENGTH = 63;

    public const string FAILURE_REASON_INVALID_LABEL_LENGTH = 'Label must be between 1 and 63 characters long';

    public const string FAILURE_REASON_INVALID_NAME_LENGTH = 'Name must be between 1 and 255 characters long';

    public const string FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE = 'Label must contain only alpha-numeric characters and hyphens, and cannot start or end with a hyphen';

    public const string FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE = 'Label must contain only alpha-numeric characters, hyphens and underscores, and cannot start or end with a hyphen';

    public const string FAILURE_REASON_GENERAL = 'Name must be between 1 and 255 characters long, and contain only alpha-numeric characters and hyphens, and cannot start or end with a hyphen, and may contain underscore if the record type allows it';

    public string $reason = '';

    private int $recordType;

    public function __construct(int $recordType)
    {
        $this->recordType = $recordType;
    }

    /**
     * Check if the provided value matches the Name record format
     *
     * @param mixed $name
     * @return bool
     */
    public function isValid(mixed $name): bool
    {
        if (!\is_string($name)) {
            $this->reason = self::FAILURE_REASON_GENERAL;
            return false;
        }

        // DNS names are made up of labels separated by dots.
        // Each label: 1-63 chars, letters, digits, hyphens, can't start/end w/ hyphen.
        // Full name: <=255 chars, labels separated by single dots, no empty labels unless root.
        // If the record type allows underscores in the name, they are allowed in the name.

        if (\strlen($name) < 1 || \strlen($name) > Domain::MAX_DOMAIN_NAME_LEN) {
            $this->reason = self::FAILURE_REASON_INVALID_NAME_LENGTH;
            return false;
        }

        // Special case for referencing the zone origin
        if ($name === '@') {
            return true;
        }

        // If the name ends with '.', strip it (absolute FQDN); allow trailing '.'.
        $trimmed = (\substr($name, -1) === '.') ? \substr($name, 0, -1) : $name;
        $labels = \explode('.', $trimmed);

        $isUnderscoreAllowed = \in_array($this->recordType, self::RECORD_TYPES_WITH_UNDERSCORE_IN_NAME);

        foreach ($labels as $label) {
            if ($label === '') {
                $this->reason = $isUnderscoreAllowed ? self::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE : self::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE;
                return false;
            }

            if (\strlen($label) > self::LABEL_MAX_LENGTH) {
                $this->reason = self::FAILURE_REASON_INVALID_LABEL_LENGTH;
                return false;
            }

            // RFC: Only a-z 0-9 -, can't start or end with '-'
            // May contain '_' if the record type allows it.
            $len = \strlen($label);
            // Check label contains only allowed chars
            for ($i = 0; $i < $len; ++$i) {
                if (!$this->isValidCharacter($label[$i], $i === 0 || $i === $len - 1, $isUnderscoreAllowed)) {
                    $this->reason = $isUnderscoreAllowed ? self::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITH_UNDERSCORE : self::FAILURE_REASON_INVALID_LABEL_CHARACTERS_WITHOUT_UNDERSCORE;
                    return false;
                }
            }
        }

        return true;
    }

    private function isValidCharacter(string $char, bool $isFirstOrLast, bool $isUnderscoreAllowed): bool
    {
        if ($isFirstOrLast) {
            return \ctype_alnum($char) || ($isUnderscoreAllowed && $char === '_');
        }
        return \ctype_alnum($char) || $char === '-' || ($isUnderscoreAllowed && $char === '_');
    }

    /**
     * @inheritDoc
     */
    public function getDescription(): string
    {
        if (!empty($this->reason)) {
            return $this->reason;
        }

        return self::FAILURE_REASON_GENERAL;
    }

    /**
     * @inheritDoc
     */
    public function getType(): string
    {
        return self::TYPE_STRING;
    }

    /**
     * @inheritDoc
     */
    public function isArray(): bool
    {
        return false;
    }
}
