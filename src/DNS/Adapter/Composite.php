<?php

namespace Utopia\DNS\Adapter;

use Utopia\DNS\Adapter;

/**
 * Fans `Server` hooks out to multiple transport adapters.
 *
 * Useful for common setups like "UDP + TCP on the same port", which
 * typically involves a shared underlying runtime (e.g. one
 * `Swoole\Server` with both a primary port and an added TCP listener).
 * Each underlying adapter is assumed to be non-blocking during
 * wiring — one of them owns the blocking event loop and is started
 * last; the others are expected to no-op their `start()`.
 */
class Composite extends Adapter
{
    /** @var list<Adapter> */
    protected array $adapters;

    public function __construct(Adapter ...$adapters)
    {
        $this->adapters = array_values($adapters);
    }

    public function setProxyProtocol(bool $enabled): void
    {
        parent::setProxyProtocol($enabled);
        foreach ($this->adapters as $adapter) {
            $adapter->setProxyProtocol($enabled);
        }
    }

    public function onWorkerStart(callable $callback): void
    {
        foreach ($this->adapters as $adapter) {
            $adapter->onWorkerStart($callback);
        }
    }

    public function onMessage(callable $callback): void
    {
        foreach ($this->adapters as $adapter) {
            $adapter->onMessage($callback);
        }
    }

    public function start(): void
    {
        foreach ($this->adapters as $adapter) {
            $adapter->start();
        }
    }

    public function getName(): string
    {
        $names = array_map(fn (Adapter $a) => $a->getName(), $this->adapters);
        return 'composite(' . implode('+', $names) . ')';
    }

    /**
     * @return list<Adapter>
     */
    public function getAdapters(): array
    {
        return $this->adapters;
    }
}
