<?php

namespace Utopia\DNS;

class Server
{
    protected array $types = [
        'A' => 1,
        'NS' => 2,
        'CNAME' => 5,
        'SOA' => 6,
        'WKS' => 11,
        'PTR' => 12,
        'HINFO' => 13,
        'MX' => 15,
        'TXT' => 16,
        'RP' => 17,
        'SIG' => 24,
        'KEY' => 25,
        'LOC' => 29,
        'NXT' => 30,
        'AAAA' => 28,
        'CERT' => 37,
        'A6' => 38,
        'AXFR' => 252,
        'IXFR' => 251,
        '*' => 255
    ];

    protected Adapter $adapter;
    protected Resolver $resolver;

    /**
     * @param Adapter $adapter
     * @param Resolver $resolver
     */
    public function __construct(Adapter $adapter, Resolver $resolver)
    {
        $this->adapter = $adapter;
        $this->resolver = $resolver;
    }
   
    public function start()
    {
        $this->adapter->onPacket(function (string $buf, string $ip, int $port)
        {
            $domain = '';
            $tmp = substr($buf,12);
            $e = strlen($tmp);
            
            for($i=0; $i < $e; $i++) {
                $len = ord($tmp[$i]);
                if ($len == 0)
                    break;
                $domain .= substr($tmp,$i+1, $len).'.';
                $i += $len;
            }
    
            $i++;$i++; /* move two char */
           
            $queryType = array_search((string)ord($tmp[$i]), $this->types ) ;
           
            $domain = substr($domain, 0, strlen($domain)-1);
            $ips = $this->resolve($domain, $queryType, $ip, $port);
    
            $answer = $buf[0].$buf[1].chr(129).chr(128).$buf[4].$buf[5].$buf[4].$buf[5].chr(0).chr(0).chr(0).chr(0);
            $answer .= $tmp;
            $answer .= chr(192).chr(12);
            $answer .= chr(0).chr(1).chr(0).chr(1).chr(0).chr(0).chr(0).chr(60).chr(0).chr(4);
            $answer .= $this->encode($ips);
    
            return $answer;
        });
        $this->adapter->start();
    }

    /**
     * Resolve domain name to IP by record type
     * 
     * @param string $domain
     * @param string $type
     * @param string $ip
     * @param int $port
     * 
     * @return string
     */
    protected function resolve(string $domain, string $type, string $ip, int $port): string
    {
        return $this->resolver->resolve($domain, $type, $ip, $port);
    }
   
    /**
     * Encode string to bytes
     * 
     * @param string $ip
     * 
     * @return string
     */
    protected function encode(string $string): string
    {
        $result = '';

        foreach(explode('.', $string) as $part) {
            $result .= chr((int)$part);
        }

        return $result;
    }
}