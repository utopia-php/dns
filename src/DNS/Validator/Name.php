<?php

namespace Utopia\DNS\Validator;

use Utopia\DNS\Message\Domain;
use Utopia\Validator;

class Name extends Validator
{
    public const int LABEL_MAX_LENGTH = 63;

    public const string FAILURE_REASON_INVALID_LABEL_LENGTH = 'Label must be between 1 and 63 characters long';

    public const string FAILURE_REASON_INVALID_NAME_LENGTH = 'Name must be between 1 and 255 characters long';

    public const string FAILURE_REASON_INVALID_LABEL_CHARACTERS = 'Label must contain only alpha-numeric characters and hyphens, and cannot start or end with a hyphen';

    public const string FAILURE_REASON_GENERAL = 'Name must be between 1 and 255 characters long, and contain only alpha-numeric characters and hyphens, and cannot start or end with a hyphen';

    public string $reason = '';

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

        if (\strlen($name) < 1 || \strlen($name) > Domain::MAX_DOMAIN_NAME_LEN) {
            $this->reason = self::FAILURE_REASON_INVALID_NAME_LENGTH;
            return false;
        }

        // If the name ends with '.', strip it (absolute FQDN); allow trailing '.'.
        $trimmed = (\substr($name, -1) === '.') ? \substr($name, 0, -1) : $name;

        $labels = \explode('.', $trimmed);

        // Disallow empty label except root "." (which means $trimmed = '')
        foreach ($labels as $label) {
            if ($label === '') {
                $this->reason = self::FAILURE_REASON_INVALID_LABEL_CHARACTERS;
                return false;
            }

            if (\strlen($label) > self::LABEL_MAX_LENGTH) {
                $this->reason = self::FAILURE_REASON_INVALID_LABEL_LENGTH;
                return false;
            }

            // RFC: Only a-z 0-9 -, can't start or end with '-'

            // Check first and last character are alphanumeric
            $len = \strlen($label);
            if (
                !\ctype_alnum($label[0]) ||
                !\ctype_alnum($label[$len - 1])
            ) {
                $this->reason = self::FAILURE_REASON_INVALID_LABEL_CHARACTERS;
                return false;
            }

            // Check label contains only allowed chars
            for ($i = 1; $i < $len - 1; ++$i) {
                $c = $label[$i];
                if (!\ctype_alnum($c) && $c !== '-') {
                    $this->reason = self::FAILURE_REASON_INVALID_LABEL_CHARACTERS;
                    return false;
                }
            }
        }

        return true;
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
