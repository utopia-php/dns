<?php

namespace Utopia\DNS\Message;

use Utopia\DNS\Exception\DecodingException;

final readonly class Question
{
    public function __construct(
        public string $name,
        public int $type,
        public int $class = Record::CLASS_IN
    ) {
    }

    /**
     * @param-out int $offset
     */
    public static function decode(string $data, int &$offset = 0): self
    {
        $name = Domain::decode($data, $offset);

        $remaining = strlen($data) - $offset;
        if ($remaining < 4) {
            throw new DecodingException('Question section truncated');
        }

        $typeData = unpack('ntype', substr($data, $offset, 2));
        if (!is_array($typeData) || !array_key_exists('type', $typeData)) {
            throw new DecodingException('Failed to unpack question type');
        }
        $type = $typeData['type'];
        $offset += 2;

        $classData = unpack('nclass', substr($data, $offset, 2));
        if (!is_array($classData) || !array_key_exists('class', $classData)) {
            throw new DecodingException('Failed to unpack question class');
        }
        $class = $classData['class'];
        $offset += 2;

        return new self($name, $type, $class);
    }

    public function encode(): string
    {
        $encodedName = Domain::encode($this->name);

        return $encodedName . pack('nn', $this->type, $this->class);
    }
}
