<?php

namespace Utopia\DNS;

abstract class Adapter
{
    /**
     * Packet Callback
     *
     * @param callable $callback
     */
    abstract public function onPacket(callable $callback): void;

    /**
     * Start the DNS server
     */
    abstract public function start(): void;

    /**
     * Get the name of the adapter
     * 
     * @return string
     */
    abstract public function getName(): string;
}
