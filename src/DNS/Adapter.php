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

    /**
     * Worker Start Callback (optional for adapters that support it)
     *
     * @param callable $callback
     */
    public function onWorkerStart(callable $callback): void
    {
        // Default implementation does nothing
        // Adapters that support worker events should override this
    }
}
