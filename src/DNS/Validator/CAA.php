<?php

namespace Utopia\DNS\Validator;

use Utopia\Validator;

class CAA extends Validator
{
    protected const int CAA_FLAG_MIN = 0;

    protected const int CAA_FLAG_MAX = 255;

    protected const string FAILURE_REASON_INVALID_FLAGS = 'Invalid flags';

    protected const string FAILURE_REASON_INVALID_TAG = 'Invalid tag';

    protected const string FAILURE_REASON_INVALID_VALUE = 'Invalid value';

    protected const string FAILURE_REASON_INVALID_FORMAT = 'Invalid format';

    public string $reason = '';

    /**
     * Check if the provided value matches the CAA record format
     *
     * @param mixed $data
     * @return bool
     */
    public function isValid(mixed $data): bool
    {
        if (!is_string($data)) {
            $this->reason = self::FAILURE_REASON_INVALID_FORMAT;
            return false;
        }

        $parts = explode(" ", $data, 3);

        if (count($parts) !== 3) {
            $this->reason = self::FAILURE_REASON_INVALID_FORMAT;
            return false;
        }

        $flags = $parts[0];
        $tag = $parts[1];
        $value = $parts[2];

        // Check flags is a number
        if (!is_numeric($flags)) {
            $this->reason = self::FAILURE_REASON_INVALID_FLAGS;
            return false;
        }

        $flags = (int) $flags;

        // Check flags is within the allowed range
        if ($flags < self::CAA_FLAG_MIN || $flags > self::CAA_FLAG_MAX) {
            $this->reason = self::FAILURE_REASON_INVALID_FLAGS;
            return false;
        }

        // Check tag is not empty
        if (strlen($tag) === 0) {
            $this->reason = self::FAILURE_REASON_INVALID_TAG;
            return false;
        }

        // Check value is not empty and starts with " and ends with "
        if (strlen($value) === 0 || $value[0] !== '"' || $value[strlen($value) - 1] !== '"') {
            $this->reason = self::FAILURE_REASON_INVALID_VALUE;
            return false;
        }

        $value = substr($value, 1, strlen($value) - 2);

        // Check value is not empty after removing the quotes
        if (strlen($value) === 0) {
            $this->reason = self::FAILURE_REASON_INVALID_VALUE;
            return false;
        }

        // All checks passed
        return true;
    }

    public function getDescription(): string
    {
        $messages = ['CAA verification failed'];

        $messages[] = !empty($this->reason) ? $this->reason : self::FAILURE_REASON_INVALID_FORMAT;

        return implode('. ', $messages) . '.';
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
