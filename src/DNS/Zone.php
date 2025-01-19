<?php

namespace Utopia\DNS;

class Zone
{
    protected int $defaultTTL = 3600;
    protected string $defaultOrigin = '';

    /**
     * Validate a DNS zone file in a BIND‑like manner.
     * Supports multi‑line records (using parentheses), $TTL and $ORIGIN directives,
     * as well as blank owner inheritance.
     *
     * @param string $domain  The default domain.
     * @param string $content The raw zone file content.
     * @return string[] An array of error messages.
     */
    public function validateZoneFile(string $domain, string $content): array
    {
        $this->defaultTTL = 3600;
        $this->defaultOrigin = $domain;
        $errors = [];
        $lastOwner = null;

        // Merge physical lines into logical records.
        $logicalLines = $this->collectLogicalLines($content);
        $lineNum = 0;
        foreach ($logicalLines as $rawLine) {
            $lineNum++;
            // Now that we have a full logical record, trim any extra whitespace.
            $line = trim($rawLine);
            if ($line === '' || $this->isComment($line)) {
                continue;
            }
            // Directives handling.
            if ($this->isDirective($line)) {
                $tokens = $this->tokenize($line);
                $dir = strtoupper($tokens[0] ?? '');
                $val = $tokens[1] ?? '';
                if ($dir === '$TTL') {
                    if (!ctype_digit($val)) {
                        $errors[] = "Line {$lineNum}: Invalid \$TTL value '{$val}' (must be integer).";
                    } else {
                        $this->defaultTTL = (int)$val;
                    }
                } elseif ($dir === '$ORIGIN') {
                    if ($val === '') {
                        $errors[] = "Line {$lineNum}: \$ORIGIN directive missing domain.";
                    } else {
                        $this->defaultOrigin = rtrim($val, '.');
                    }
                } else {
                    $errors[] = "Line {$lineNum}: Unsupported directive '{$line}'.";
                }
                continue;
            }
            // Record line parsing.
            $tokens = $this->tokenize($line);
            if (count($tokens) < 4) {
                // Skip lines that don't have enough tokens.
                continue;
            }
            // 1) Determine the owner.
            $owner = null;
            $pos = 0;
            if ($this->isLikelyOwner($tokens[0])) {
                $owner = $tokens[0];
                $pos++;
                $lastOwner = $owner;
            } else {
                if (!$lastOwner) {
                    $errors[] = "Line {$lineNum}: No previous owner to reuse for blank/implicit owner.";
                    continue;
                }
                $owner = $lastOwner;
            }
            // 2) TTL: if the next token is numeric, that's the TTL; otherwise use the default.
            $ttl = (isset($tokens[$pos]) && ctype_digit($tokens[$pos])) ? (int)$tokens[$pos++] : $this->defaultTTL;
            // 3) Class must be the next token and it should be "IN".
            if (!isset($tokens[$pos])) {
                $errors[] = "Line {$lineNum}: Missing class.";
                continue;
            }
            $origClass = $tokens[$pos];
            $class = strtoupper($origClass);
            $pos++;
            if ($class !== 'IN') {
                $errors[] = "Line {$lineNum}: Unsupported class '{$origClass}' (only 'IN').";
            }
            // 4) Next token is the record type.
            if (!isset($tokens[$pos])) {
                $errors[] = "Line {$lineNum}: Missing record type.";
                continue;
            }
            $origType = $tokens[$pos];
            $type = strtoupper($origType);
            $pos++;
            // 5) Remaining tokens are the record data.
            $dataParts = array_slice($tokens, $pos);
            $data = implode(' ', $dataParts);

            // Basic validation for known record types.
            switch ($type) {
                case 'A':
                    if (!$this->isIPv4($data)) {
                        $errors[] = "Line {$lineNum}: Not a valid IPv4 '{$data}'.";
                    }
                    break;
                case 'AAAA':
                    if (!$this->isIPv6($data)) {
                        $errors[] = "Line {$lineNum}: Not a valid IPv6 '{$data}'.";
                    }
                    break;
                case 'CNAME':
                case 'NS':
                case 'SOA':
                case 'TXT':
                    if ($data === '') {
                        $errors[] = "Line {$lineNum}: {$type} record has empty data.";
                    }
                    break;
                case 'MX':
                    $mx = $this->tokenize($data);
                    if (count($mx) < 2) {
                        $errors[] = "Line {$lineNum}: MX needs priority & exchange.";
                    } else {
                        [$prio, $exch] = $mx;
                        if (!ctype_digit($prio)) {
                            $errors[] = "Line {$lineNum}: Invalid MX priority '{$prio}'.";
                        }
                        if ($exch === '') {
                            $errors[] = "Line {$lineNum}: MX exchange is empty.";
                        }
                    }
                    break;
                case 'SRV':
                    $srv = $this->tokenize($data);
                    if (count($srv) < 4) {
                        $errors[] = "Line {$lineNum}: SRV must have 4 parts.";
                    } else {
                        [$prio, $weight, $port, $tgt] = $srv;
                        if (!ctype_digit($prio)) {
                            $errors[] = "Line {$lineNum}: Invalid SRV priority '{$prio}'.";
                        }
                        if (!ctype_digit($weight)) {
                            $errors[] = "Line {$lineNum}: Invalid SRV weight '{$weight}'.";
                        }
                        if (!ctype_digit($port)) {
                            $errors[] = "Line {$lineNum}: Invalid SRV port '{$port}'.";
                        }
                        if ($tgt === '') {
                            $errors[] = "Line {$lineNum}: SRV target is empty.";
                        }
                    }
                    break;
                default:
                    $errors[] = "Line {$lineNum}: Unknown record type '{$origType}'.";
                    break;
            }
        }
        return $errors;
    }

    /**
     * Import a DNS zone file, returning an array of Record objects.
     * Supports merging multi‑line records, directives, and blank owner inheritance.
     *
     * @param string $domain  The default domain.
     * @param string $content The raw zone file content.
     * @return Record[] Array of record objects.
     */
    public function import(string $domain, string $content): array
    {
        $this->defaultTTL = 3600;
        $this->defaultOrigin = $domain;
        $records = [];
        $lastOwner = null;
        $logicalLines = $this->collectLogicalLines($content);
        foreach ($logicalLines as $rawLine) {
            $line = trim($this->stripTrailingComment($rawLine));
            if ($line === '' || $this->isComment($line)) {
                continue;
            }
            if ($this->isDirective($line)) {
                $tokens = $this->tokenize($line);
                $dir = strtoupper($tokens[0] ?? '');
                $val = $tokens[1] ?? '';
                if ($dir === '$TTL' && ctype_digit($val)) {
                    $this->defaultTTL = (int)$val;
                } elseif ($dir === '$ORIGIN') {
                    $this->defaultOrigin = rtrim($val, '.');
                }
                continue;
            }
            $tokens = $this->tokenize($line);
            if (count($tokens) < 4) {
                continue;
            }
            $owner = null;
            $pos = 0;
            if ($this->isLikelyOwner($tokens[0])) {
                $owner = $tokens[0];
                $pos++;
                $lastOwner = $owner;
            } else {
                if (!$lastOwner) {
                    continue;
                }
                $owner = $lastOwner;
            }
            $ttl = (isset($tokens[$pos]) && ctype_digit($tokens[$pos])) ? (int)$tokens[$pos++] : $this->defaultTTL;
            if (!isset($tokens[$pos]) || strtoupper($tokens[$pos]) !== 'IN') {
                continue;
            }
            $pos++; // skip "IN"
            if (!isset($tokens[$pos])) {
                continue;
            }
            $type = strtoupper($tokens[$pos++]);
            $dataParts = array_slice($tokens, $pos);
            $data = implode(' ', $dataParts);
            if ($owner !== '@' && !str_ends_with($owner, '.')) {
                $owner .= '.' . rtrim($this->defaultOrigin, '.');
            }
            $rec = new Record($owner, $ttl, 'IN', $type, $data);
            if ($type === 'MX') {
                $mx = $this->tokenize($data);
                if (count($mx) === 2) {
                    $rec->setPriority((int)$mx[0]);
                    $rec->setRdata($mx[1]);
                }
            } elseif ($type === 'SRV') {
                $srv = $this->tokenize($data);
                if (count($srv) === 4) {
                    $rec->setPriority((int)$srv[0]);
                    $rec->setWeight((int)$srv[1]);
                    $rec->setPort((int)$srv[2]);
                    $rec->setRdata($srv[3]);
                }
            }
            $records[] = $rec;
        }
        return $records;
    }

    /**
     * Export an array of Record objects into a zone file string (one record per line).
     *
     * @param string $domain  The domain (not used in formatting).
     * @param Record[] $records Array of records.
     * @return string The zone file output.
     */
    public function export(string $domain, array $records): string
    {
        $lines = [];
        foreach ($records as $r) {
            $owner = $r->getName();
            $ttl = $r->getTTL();
            $class = $r->getClass();
            $type = $r->getTypeName();
            $data = $r->getRdata();

            if ($type === 'MX' && $r->getPriority() !== null) {
                $data = "{$r->getPriority()} {$r->getRdata()}";
            } elseif ($type === 'SRV' && $r->getPriority() !== null && $r->getWeight() !== null && $r->getPort() !== null) {
                $data = "{$r->getPriority()} {$r->getWeight()} {$r->getPort()} {$r->getRdata()}";
            }

            $lines[] = sprintf("%s %d %s %s %s", $owner, $ttl, $class, $type, $data);
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * Merge physical lines into "logical" lines by handling parentheses.
     * For each physical line, we remove trailing comments, then merge lines if
     * the record is multi‑line.
     *
     * If a closing ')' is found and there is trailing text, that trailing text is split
     * into a new logical line.
     *
     * @param string $content The raw content.
     * @return string[] An array of merged record lines.
     */
    protected function collectLogicalLines(string $content): array
    {
        // Normalize line breaks.
        $content = str_replace(["\r\n", "\r"], "\n", $content);
        $rawLines = explode("\n", $content);
        $logicalLines = [];
        $accum = '';
        $parenDepth = 0;
        foreach ($rawLines as $rawLine) {
            // Remove trailing comments from the physical line.
            $line = trim($this->stripTrailingComment($rawLine));
            if ($line === '') {
                continue;
            }
            // Count the number of '(' and ')' in the physical line.
            $openCount = substr_count($line, '(');
            $closeCount = substr_count($line, ')');
            $parenDepth += $openCount - $closeCount;
            // Append the processed line.
            if ($accum === '') {
                $accum = $line;
            } else {
                $accum .= ' ' . $line;
            }
            // If the multi-line record is complete...
            if ($parenDepth <= 0) {
                // If there is trailing text after the last ')', split it out.
                $lastClosePos = strrpos($accum, ')');
                if ($lastClosePos !== false && $lastClosePos < strlen($accum) - 1) {
                    $recordPart = substr($accum, 0, $lastClosePos + 1);
                    $trailingPart = trim(substr($accum, $lastClosePos + 1));
                    $logicalLines[] = trim($recordPart);
                    if ($trailingPart !== '') {
                        $logicalLines[] = $trailingPart;
                    }
                } else {
                    $logicalLines[] = trim($accum);
                }
                $accum = '';
                $parenDepth = 0;
            }
        }
        if (trim($accum) !== '') {
            $logicalLines[] = trim($accum);
        }
        return array_filter($logicalLines, function ($line) {
            return $line !== '';
        });
    }

    /**
     * Remove trailing comments (anything after '#' or ';') from a line.
     */
    protected function stripTrailingComment(string $line): string
    {
        $hashPos = strpos($line, '#');
        if ($hashPos !== false) {
            $line = substr($line, 0, $hashPos);
        }
        $semiPos = strpos($line, ';');
        if ($semiPos !== false) {
            $line = substr($line, 0, $semiPos);
        }
        return $line;
    }

    protected function isComment(string $line): bool
    {
        $t = ltrim($line);
        return (isset($t[0]) && ($t[0] === '#' || $t[0] === ';'));
    }

    /**
     * Tokenize a line by whitespace.
     *
     * @return string[]
     */
    protected function tokenize(string $line): array
    {
        $tokens = [];
        $current = '';
        $inSpace = true;
        for ($i = 0, $len = strlen($line); $i < $len; $i++) {
            $c = $line[$i];
            if ($c === ' ' || $c === "\t") {
                if (!$inSpace) {
                    $tokens[] = $current;
                    $current = '';
                }
                $inSpace = true;
            } else {
                $current .= $c;
                $inSpace = false;
            }
        }
        if ($current !== '') {
            $tokens[] = $current;
        }
        return $tokens;
    }

    protected function isDirective(string $line): bool
    {
        $t = ltrim($line);
        return (isset($t[0]) && $t[0] === '$');
    }

    /**
     * Determine if a token is likely an owner name.
     */
    protected function isLikelyOwner(string $token): bool
    {
        $t = strtoupper($token);
        if ($t === 'IN') {
            return false;
        }
        if (ctype_digit($t)) {
            return false;
        }
        if (strpos($t, '$') === 0) {
            return false;
        }
        return true;
    }

    protected function isIPv4(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    protected function isIPv6(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }
}
