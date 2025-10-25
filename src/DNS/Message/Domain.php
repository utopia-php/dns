<?php

namespace Utopia\DNS\Message;

final class Domain
{
    public const int MAX_LABEL_LEN = 63;
    public const int MAX_LABELS = 127;
    public const int MAX_DOMAIN_NAME_LEN = 255;

    /**
     * Encode a domain name according to RFC 1035.
     *
     * @param string $name
     * @return string
     */
    public static function encode(string $name): string
    {
        if ($name === '') {
            return "\x00";
        }

        $trimmed = rtrim($name, '.');
        if ($trimmed === '') {
            return "\x00";
        }

        $labels = explode('.', $trimmed);
        $labelCount = count($labels);

        if ($labelCount > self::MAX_LABELS) {
            throw new \InvalidArgumentException("Domain has too many labels: {$labelCount}");
        }

        $encoded = '';
        $totalLength = 0;

        foreach ($labels as $label) {
            if ($label === '') {
                throw new \InvalidArgumentException('Domain labels must not be empty');
            }

            $labelLength = strlen($label);

            if ($labelLength > self::MAX_LABEL_LEN) {
                throw new \InvalidArgumentException("Label too long: {$label}");
            }

            $encoded .= chr($labelLength) . $label;
            $totalLength += $labelLength + 1; // length byte + label
        }

        $totalLength += 1; // trailing zero-length octet

        if ($totalLength > self::MAX_DOMAIN_NAME_LEN) {
            throw new \InvalidArgumentException(
                "Encoded domain exceeds maximum length of " . self::MAX_DOMAIN_NAME_LEN . ' bytes'
            );
        }

        return $encoded . "\x00";
    }
}
