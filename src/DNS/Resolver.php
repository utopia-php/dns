<?php

namespace Utopia\DNS;

abstract class Resolver
{
    /**
     * Resolve DNS Record
     *
     * @param Message $query
     * @return Message
     */
    abstract public function resolve(Message $query): Message;

    /**
     * Get the name of the resolver
     *
     * @return string
     */
    abstract public function getName(): string;
}
