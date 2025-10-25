<?php

namespace Utopia\DNS;

use Utopia\DNS\Message\Record;

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
    public function validate(string $domain, string $content): array
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
            // For TXT records, only strip comments at #, not at semicolons
            $isTxt = false;
            $peekTokens = $this->tokenize($rawLine);
            foreach ($peekTokens as $tok) {
                if (strtoupper($tok) === 'TXT') {
                    $isTxt = true;
                    break;
                }
            }
            if ($isTxt) {
                $line = trim($this->stripTrailingComment($rawLine, true));
            } else {
                $line = trim($this->stripTrailingComment($rawLine, false));
            }
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
            $typeName = strtoupper($tokens[$pos++]);
            $typeCode = Record::typeNameToCode($typeName);
            if ($typeCode === null) {
                continue;
            }

            $dataParts = array_slice($tokens, $pos);
            $data = $typeName === 'TXT'
                ? implode('', $dataParts)
                : implode(' ', $dataParts);

            $priority = $weight = $port = null;

            if ($typeName === 'MX') {
                $mx = $this->tokenize($data);
                if (count($mx) === 2) {
                    $priority = (int)$mx[0];
                    $data = $mx[1];
                }
            } elseif ($typeName === 'SRV') {
                $srv = $this->tokenize($data);
                if (count($srv) === 4) {
                    $priority = (int)$srv[0];
                    $weight = (int)$srv[1];
                    $port = (int)$srv[2];
                    $data = $srv[3];
                }
            }

            if ($owner !== '@' && !str_ends_with($owner, '.')) {
                $owner .= '.' . rtrim($this->defaultOrigin, '.');
            }

            $records[] = new Record(
                name: $owner,
                type: $typeCode,
                class: Record::CLASS_IN,
                ttl: $ttl,
                rdata: $data,
                priority: $priority,
                weight: $weight,
                port: $port
            );
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
            $owner = $r->name;
            $ttl = $r->ttl;
            $class = $r->class === Record::CLASS_IN ? 'IN' : (string)$r->class;
            $type = Record::typeCodeToName($r->type) ?? (string)$r->type;
            $data = $r->rdata;

            if ($r->type === Record::TYPE_MX && $r->priority !== null) {
                $data = "{$r->priority} {$r->rdata}";
            } elseif (
                $r->type === Record::TYPE_SRV
                && $r->priority !== null
                && $r->weight !== null
                && $r->port !== null
            ) {
                $data = "{$r->priority} {$r->weight} {$r->port} {$r->rdata}";
            } elseif ($r->type === Record::TYPE_TXT) {
                // Encode TXT records with double quotes and escape embedded quotes and backslashes
                $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $data);
                $data = '"' . $escaped . '"';
            }

            $lines[] = sprintf("%s %d %s %s %s", $owner, $ttl, $class, $type, $data);
        }
        // Remove any empty lines at the end
        while (!empty($lines) && trim(end($lines)) === '') {
            array_pop($lines);
        }
        $output = implode("\n", $lines);
        // Guarantee only a single newline at the end
        return rtrim($output, "\n") . "\n";
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
            $line = trim($this->stripTrailingComment($rawLine, false));
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

    /**
     * Remove trailing comments (anything after '#' or ';') from a line.
     * If $txtMode is true, only strip at #, not at semicolons.
     */
    protected function stripTrailingComment(string $line, bool $txtMode): string
    {
        $inQuote = false;
        $result = '';
        for ($i = 0, $len = strlen($line); $i < $len; $i++) {
            $c = $line[$i];
            // Check for unescaped quote
            if ($c === '"') {
                $escaped = false;
                $j = $i - 1;
                while ($j >= 0 && $line[$j] === '\\') {
                    $escaped = !$escaped;
                    $j--;
                }
                if (!$escaped) {
                    $inQuote = !$inQuote;
                }
            }
            if (!$inQuote && ($c === '#' || (!$txtMode && $c === ';'))) {
                break;
            }
            $result .= $c;
        }
        return $result;
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
    /**
     * Tokenize a line by whitespace, handling quoted strings and escapes per RFC 1035.
     *
     * @return string[]
     */
    protected function tokenize(string $line): array
    {
        // Manual tokenizer: handles quoted strings and escapes
        $tokens = [];
        $current = '';
        $inQuote = false;
        $escape = false;
        for ($i = 0, $len = strlen($line); $i < $len; $i++) {
            $c = $line[$i];
            if ($escape) {
                $current .= $c;
                $escape = false;
                continue;
            }
            if ($c === '\\') {
                $escape = true;
                continue;
            }
            if ($inQuote) {
                if ($c === '"') {
                    $inQuote = false;
                    $tokens[] = $current;
                    $current = '';
                } else {
                    $current .= $c;
                }
            } else {
                if ($c === '"') {
                    $inQuote = true;
                } elseif ($c === ' ' || $c === "\t") {
                    if ($current !== '') {
                        $tokens[] = $current;
                        $current = '';
                    }
                } else {
                    $current .= $c;
                }
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
