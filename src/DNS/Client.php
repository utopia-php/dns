<?php

namespace Utopia\DNS;

use Exception;

class Client
{
    /** @var \Socket */
    protected $socket;
    protected string $server;
    protected int $port;
    protected int $timeout;

    public function __construct(string $server = '127.0.0.1', int $port = 53, int $timeout = 5)
    {
        $this->port = $port;
        $this->timeout = $timeout;

        if (!filter_var($server, FILTER_VALIDATE_IP)) {
            $resolved = gethostbyname($server);
            if ($resolved === $server) {
                throw new Exception("Failed to resolve DNS server hostname: {$server}");
            }
            $this->server = $resolved;
        } else {
            $this->server = $server;
        }

        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

        if ($socket === false) {
            throw new Exception('Failed to create socket: ' . socket_strerror(socket_last_error()));
        }

        // Set socket timeout
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $timeout, 'usec' => 0]);
        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $timeout, 'usec' => 0]);

        $this->socket = $socket;
    }

    /**
     * @param Message $message
     * @return Message
     */
    public function query(Message $message): Message
    {
        $packet = $message->encode();
        if (socket_sendto($this->socket, $packet, strlen($packet), 0, $this->server, $this->port) === false) {
            throw new Exception('Failed to send data: ' . socket_strerror(socket_last_error($this->socket)));
        }

        $data = '';
        $from = '';
        $port = 0;

        $result = socket_recvfrom($this->socket, $data, 512, 0, $from, $port);

        if ($result === false) {
            $error = socket_last_error($this->socket);
            $errorMessage = socket_strerror($error);
            throw new Exception("Failed to receive data from $this->server: $errorMessage (Error code: $error)");
        }

        if (empty($data)) {
            throw new Exception("Empty response received from $this->server:$this->port");
        }

        $response = Message::decode($data);
        if ($response->header->id !== $message->header->id) {
            throw new Exception("Mismatched DNS transaction ID. Expected {$message->header->id}, got {$response->header->id}");
        }

        return $response;
    }
}
