<?php

namespace Utopia\DNS;

use Exception;
use Utopia\DNS\Message\Question;

class Client
{
    /** @var \Socket */
    protected $socket;
    protected string $server;
    protected int $port;
    protected int $timeout;

    public function __construct(string $server = '127.0.0.1', int $port = 53, int $timeout = 5)
    {
        $this->server = $server;
        $this->port = $port;
        $this->timeout = $timeout;

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
     * @param Question $question
     * @return Message
     */
    public function query(Question $question): Message
    {
        try {
            $message = Message::query($question);
            $packet = $message->encode();
            if (socket_sendto($this->socket, $packet, strlen($packet), 0, $this->server, $this->port) === false) {
                throw new Exception('Failed to send data: ' . socket_strerror(socket_last_error($this->socket)));
            }

            $response = '';
            $from = '';
            $port = 0;

            $result = socket_recvfrom($this->socket, $response, 512, 0, $from, $port);

            if ($result === false) {
                $error = socket_last_error($this->socket);
                $errorMessage = socket_strerror($error);
                throw new Exception("Failed to receive data from {$this->server}: {$errorMessage} (Error code: {$error})");
            }

            if (empty($response)) {
                throw new Exception("Empty response received from {$this->server}:{$this->port}");
            }

            $response = Message::decode($response);
            if ($response->header->id !== $message->header->id) {
                throw new Exception("Mismatched DNS transaction ID. Expected {$message->header->id}, got {$response->header->id}");
            }

            return $response;
        } catch (Exception $e) {
            throw new Exception($e->getMessage(), $e->getCode(), $e);
        }
    }
}
