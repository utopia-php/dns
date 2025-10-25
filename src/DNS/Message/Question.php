<?php

namespace Utopia\DNS\Message;

final class Question
{
    public function __construct(
        public readonly string $name,
        public readonly int $type,
        public readonly int $class = Record::CLASS_IN
    ) {
    }

    /**
     * @param-out int $offset
     */
    public static function decode(string $data, int &$offset = 0): self
    {
        $name = self::decodeName($data, $offset);

        $typeData = unpack('ntype', substr($data, $offset, 2));
        if (!is_array($typeData) || !array_key_exists('type', $typeData)) {
            throw new \InvalidArgumentException('Failed to unpack question type');
        }
        $type = $typeData['type'];
        $offset += 2;

        $classData = unpack('nclass', substr($data, $offset, 2));
        if (!is_array($classData) || !array_key_exists('class', $classData)) {
            throw new \InvalidArgumentException('Failed to unpack question class');
        }
        $class = $classData['class'];
        $offset += 2;

        return new self($name, $type, $class);
    }

    /**
     * Decode a domain name while respecting DNS compression pointers.
     *
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

    public function encode(): string
    {
        $encodedName = Domain::encode($this->name);

        return $encodedName . pack('nn', $this->type, $this->class);
    }
}
