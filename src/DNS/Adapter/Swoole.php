<?php

namespace Utopia\DNS\Adapter;

use Swoole\Runtime;
use Utopia\DNS\Adapter;
use Swoole\Server;
use Swoole\Server\Port;
use Utopia\DNS\Message;

class Swoole extends Adapter
{
    protected Server $server;

    protected ?Port $tcpPort = null;

    /** @var callable(string $buffer, string $ip, int $port): string */
    protected mixed $onPacket;

    protected string $host;
    protected int $port;

    protected bool $enableTcp;

    protected int $maxUdpSize = 512;

    public function __construct(string $host = '0.0.0.0', int $port = 53, bool $enableTcp = true)
    {
        $this->host = $host;
        $this->port = $port;
        $this->enableTcp = $enableTcp;
        $this->server = new Server($this->host, $this->port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

        if ($this->enableTcp) {
            $this->tcpPort = $this->server->addListener($this->host, $this->port, SWOOLE_SOCK_TCP);

            $this->tcpPort->set([
                'open_length_check' => true,
                'package_length_type' => 'n',
                'package_length_offset' => 0,
                'package_body_offset' => 2,
                'package_max_length' => 65537,
            ]);
        }
    }

    /**
     * Worker start callback
     *
     * @param callable(int $workerId): void $callback
     */
    public function onWorkerStart(callable $callback): void
    {
        $this->server->on('WorkerStart', function ($server, $workerId) use ($callback) {
            \call_user_func($callback, $workerId);
        });
    }

    /**
     * @param callable $callback
     * @phpstan-param callable(string $buffer, string $ip, int $port):string $callback
     */
    public function onPacket(callable $callback): void
    {
        $this->onPacket = $callback;

        $this->server->on('Packet', function ($server, $data, $clientInfo) {
            $ip = $clientInfo['address'] ?? '';
            $port = (int) ($clientInfo['port'] ?? 0);
            $answer = \call_user_func($this->onPacket, $data, $ip, $port);

            // Swoole UDP sockets reject zero-length payloads; skip responding instead.
            if ($answer === '') {
                return;
            }

            if (strlen($answer) > $this->maxUdpSize) {
                $answer = $this->truncateResponse($answer);
            }

            $server->sendto($ip, $port, $answer);
        });

        if ($this->tcpPort instanceof Port) {
            $this->tcpPort->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
                $info = $server->getClientInfo($fd, $reactorId) ?: [];
                $ip = $info['remote_ip'] ?? '';
                $port = $info['remote_port'] ?? 0;

                $payload = substr($data, 2); // strip 2-byte length prefix
                $answer = \call_user_func($this->onPacket, $payload, $ip, $port);

                if ($answer === '') {
                    return;
                }

                $frame = pack('n', strlen($answer)) . $answer;
                $server->send($fd, $frame);
            });
        }
    }

    /**
     * Start the DNS server
     */
    public function start(): void
    {
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

    protected function truncateResponse(string $encodedResponse): string
    {
        try {
            $message = Message::decode($encodedResponse);

            $truncatedMessage = Message::response(
                $message->header,
                $message->header->responseCode,
                questions: $message->questions,
                answers: [],
                authority: [],
                additional: [],
                authoritative: $message->header->authoritative,
                truncated: true,
                recursionAvailable: $message->header->recursionAvailable
            );

            return $truncatedMessage->encode();
        } catch (\Throwable $e) {
            return $encodedResponse;
        }
    }
}
