<?php

namespace Utopia\DNS\Validator;

use Utopia\DNS\Message\Domain;
use Utopia\Validator;

class Name extends Validator
{
    public function isValid(mixed $name): bool
    {
        if (!is_string($name)) {
            return false;
        }

        // DNS names are made up of labels separated by dots.
        // Each label: 1-63 chars, letters, digits, hyphens, can't start/end w/ hyphen.
        // Full name: <=255 chars, labels separated by single dots, no empty labels unless root.

        if (strlen($name) < 1 || strlen($name) > Domain::MAX_DOMAIN_NAME_LEN) {
            return false;
        }

        // If the name ends with '.', strip it (absolute FQDN); allow trailing '.'.
        $trimmed = (substr($name, -1) === '.') ? substr($name, 0, -1) : $name;

        $labels = explode('.', $trimmed);

        // Disallow empty label except root "." (which means $trimmed = '')
        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63 || strlen($label) < 1) {
                return false;
            }
            // RFC: Only a-z 0-9 -, can't start or end with '-'

            // Check first and last character are alphanumeric
            $len = strlen($label);
            if (
                $len < 1 ||
                !ctype_alnum($label[0]) ||
                !ctype_alnum($label[$len - 1])
            ) {
                return false;
            }

            // Check label contains only allowed chars
            for ($i = 0; $i < $len - 1; ++$i) {
                $c = $label[$i];
                if (!ctype_alnum($c) && $c !== '-') {
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
        return 'Invalid name for DNS record';
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
