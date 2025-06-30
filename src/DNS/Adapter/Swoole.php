<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;

class Swoole extends Adapter
{
    protected Server $server;
    protected string $host;
    protected int $port;
    protected array $settings = [];

    public function __construct(string $host = '0.0.0.0', int $port = 53)
    {
        $this->host = $host;
        $this->port = $port;
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

        $workerNum = max(2, swoole_cpu_num() * 2); // 2x CPU cores for I/O-bound workload, minimum 2

        $this->settings = [
            'worker_num' => $workerNum,     // Auto-detected: 2x CPU cores for I/O-bound workload
            'max_coroutine' => 10000,       // High coroutine limit for concurrent API requests
            'enable_coroutine' => true,     // Enable coroutines
            'max_request' => 10000,         // Restart workers after 10k requests to prevent memory leaks
            'dispatch_mode' => 2,           // Fixed dispatch mode for UDP
        ];
    }

    /**
     * Override server settings
     *
     * @param array $settings
     * @return self
     */
    public function setSettings(array $settings): self
    {
        $this->settings = array_merge($this->settings, $settings);
        return $this;
    }

    /**
     * Set a single server setting
     *
     * @param string $key
     * @param mixed $value
     * @return self
     */
    public function setSetting(string $key, $value): self
    {
        $this->settings[$key] = $value;
        return $this;
    }

    /**
     * Get current server settings
     *
     * @return array
     */
    public function getSettings(): array
    {
        return $this->settings;
    }

    /**
     * Set the number of worker processes
     *
     * @param int $workerNum
     * @return self
     */
    public function setWorkerNum(int $workerNum): self
    {
        return $this->setSetting('worker_num', $workerNum);
    }

    /**
     * Set the maximum number of coroutines
     *
     * @param int $maxCoroutine
     * @return self
     */
    public function setMaxCoroutine(int $maxCoroutine): self
    {
        return $this->setSetting('max_coroutine', $maxCoroutine);
    }

    /**
     * Set the maximum requests per worker before restart
     *
     * @param int $maxRequest
     * @return self
     */
    public function setMaxRequest(int $maxRequest): self
    {
        return $this->setSetting('max_request', $maxRequest);
    }

    /**
     * @param callable $callback
     */
    public function onPacket(callable $callback): void
    {
        $this->server->on('Packet', function ($server, $data, $clientInfo) use ($callback) {
            $ip = $clientInfo['address'] ?? '';
            $port = $clientInfo['port'] ?? '';
            $answer = call_user_func($callback, $data, $ip, $port);

            $server->sendto($ip, $port, $answer);
        });
    }

    /**
     * Set callback for worker start event
     *
     * @param callable $callback
     */
    public function onWorkerStart(callable $callback): void
    {
        $this->server->on('WorkerStart', function ($server, $workerId) use ($callback) {
            call_user_func($callback, $server, $workerId);
        });
    }

    /**
     * Get the server instance for configuration
     *
     * @return Server
     */
    public function getServer(): Server
    {
        return $this->server;
    }

    /**
     * Start the DNS server
     */
    public function start(): void
    {
        // Apply settings before starting
        $this->server->set($this->settings);

        Runtime::enableCoroutine();
        $this->server->start();
    }

    /**
     * Get the name of the adapter
     *
     * @return string
     */
    public function getName(): string
    {
        return 'swoole';
    }
}
