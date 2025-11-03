<?php

namespace Utopia\DNS;

/**
 *
 */
interface Resolver
{
    /**
     * Returns the name of the provider.
     *
     * @return string The name of the provider.
     */
    public function getName(): string;

    /**
     * Returns a DNS response for the given query.
     *
     * @param Message $query The DNS query.
     * @return Message The DNS response.
     */
    public function resolve(Message $query): Message;
}
