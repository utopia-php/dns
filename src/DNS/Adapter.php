<?php

namespace Utopia\DNS;

abstract class Adapter
{   
    /**
     * Packet Callback
     * 
     * @param callable $callback
     */
    abstract public function onPacket(callable $callback);

    /**
     * Start the DNS server
     */
    abstract public function start();
}