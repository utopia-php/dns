<?php

/**
 * DNS Server Benchmark Tool
 *
 * This script performs load testing and benchmarking of DNS servers. It measures response times,
 * throughput, and latency distribution under concurrent load.
 *
 * Usage:
 *   php tests/benchmark.php [options]
 *
 * Options:
 *   --server=<ip>        DNS server IP address (default: 127.0.0.1)
 *   --port=<port>        DNS server port (default: 5300)
 *   --iterations=<n>     Number of queries per record type (default: 10000)
 *   --concurrency=<n>    Number of concurrent requests (default: 10)
 *
 * Additional Options:
 *   --domains=<list>     Comma-separated list of domains to test (default: dev.appwrite.io,dev2.appwrite.io)
 *   --types=<list>       Comma-separated list of record types to test (default: A,AAAA,CNAME,TXT,NS)
 *
 * Example:
 *   php tests/benchmark.php --server=127.0.0.1 --port=5300 --iterations=1000 --concurrency=20
 * Example with domains and types:
 *   php tests/benchmark.php --domains="example.com,example.org" --types="A,MX,TXT"
 *
 * Test Domains:
 *   - dev.appwrite.io (A, AAAA, CNAME, TXT, NS records)
 *   - dev2.appwrite.io (A, AAAA, CNAME, TXT, NS records)
 *   - server.appwrite.io (SRV records)
 *   - mail.appwrite.io (MX records)
 *
 * Requirements:
 *   - PHP 8.0 or higher
 *   - DNS server running and accessible
 *   - Sufficient system resources for concurrent processes
 *
 * Output:
 *   - Real-time query results
 *   - Response time statistics (min, max, avg)
 *   - Latency distribution (p50, p75, p90, p95, p99)
 *   - Time series analysis
 *   - Requests per second (RPS)
 *   - Detailed error reporting on failure
 */

require __DIR__ . '/../vendor/autoload.php';

use Utopia\CLI\Console;

function calculatePercentile(array $values, float $percentile): float
{
    sort($values);
    $index = ceil($percentile * count($values)) - 1;
    return $values[$index];
}

function benchmarkDnsServer($server, $port, $testCases, $iterations = 100, $concurrency = 10)
{
    echo "Benchmarking DNS Server: $server:$port ($iterations queries per record, concurrency: $concurrency)...\n";

    $successCount = 0;
    $failedCount = 0;
    $responseTimes = [];
    $timeSeriesData = [];
    $startTime = microtime(true);

    // Create temporary directory for process communication
    $tmpDir = sys_get_temp_dir() . '/dns_benchmark_' . uniqid();
    if (!mkdir($tmpDir, 0777, true)) {
        Console::error("Failed to create temporary directory: {$tmpDir}");
        exit(1);
    }

    foreach ($testCases as $domain => $queryTypes) {
        foreach ($queryTypes as $queryType) {
            for ($i = 0; $i < $iterations; $i += $concurrency) {
                $processes = [];
                $pipes = [];
                $batch = min($concurrency, $iterations - $i);

                // Start concurrent processes
                for ($j = 0; $j < $batch; $j++) {
                    $resultFile = "{$tmpDir}/result_{$j}.json";
                    $cmd = PHP_BINARY . ' -r \'
                        require_once "' . __DIR__ . '/../vendor/autoload.php";
                        $client = new \Utopia\DNS\Client("' . $server . '", ' . $port . ');
                        $start = microtime(true);
                        try {
                            $tmpDir = "' . $tmpDir . '";
                            if (!is_dir($tmpDir)) {
                                mkdir($tmpDir, 0777, true);
                            }
                            $records = $client->query("' . $domain . '", "' . $queryType . '");
                            $time = (microtime(true) - $start) * 1000;
                            $result = json_encode([
                                "success" => count($records) > 0,
                                "time" => $time,
                                "domain" => "' . $domain . '",
                                "type" => "' . $queryType . '"
                            ]);
                            if ($result === false) {
                                throw new Exception("Failed to encode JSON result");
                            }
                            if (file_put_contents("' . $resultFile . '", $result) === false) {
                                throw new Exception("Failed to write result file: ' . $resultFile . '");
                            }
                        } catch (Exception $e) {
                            $error = json_encode([
                                "success" => false,
                                "error" => $e->getMessage(),
                                "domain" => "' . $domain . '",
                                "type" => "' . $queryType . '"
                            ]);
                            @file_put_contents("' . $resultFile . '", $error);
                        }
                    \'';

                    $processes[$j] = proc_open($cmd, [], $pipes[$j]);
                }

                // Wait for all processes to complete and collect results
                foreach ($processes as $j => $process) {
                    proc_close($process);
                    $resultFile = "{$tmpDir}/result_{$j}.json";

                    // Wait for result file with timeout
                    $timeout = 5; // 5 seconds timeout
                    $start = time();
                    while (!file_exists($resultFile) && (time() - $start) < $timeout) {
                        usleep(10000); // Wait 10ms
                    }

                    if (file_exists($resultFile)) {
                        $content = file_get_contents($resultFile);
                        if ($content === false) {
                            Console::error("Failed to read result file: {$resultFile}");
                            continue;
                        }

                        $result = json_decode($content, true);
                        if ($result === null) {
                            Console::error("Failed to decode JSON from file: {$resultFile}");
                            continue;
                        }

                        @unlink($resultFile); // Clean up individual result file

                        if (isset($result['error'])) {
                            Console::error("\n[FAILURE DETECTED] Test stopped on first error");
                            Console::error("Domain: {$result['domain']}");
                            Console::error("Query Type: {$result['type']}");
                            Console::error("Iteration: " . ($i + $j));
                            Console::error("Error Message: {$result['error']}");
                            printFailureStats($successCount, $responseTimes, $timeSeriesData);
                            cleanupTmpDir($tmpDir);
                            exit(1);
                        }

                        if ($result['success']) {
                            $elapsedTime = (microtime(true) - $startTime) * 1000;
                            $responseTimes[] = $result['time'];
                            $timeSeriesData[] = [
                                'time' => $elapsedTime,
                                'latency' => $result['time'],
                                'domain' => $result['domain'],
                                'type' => $result['type']
                            ];
                            $successCount++;

                            $currentAvg = array_sum($responseTimes) / count($responseTimes);
                            echo "Query " . ($i + $j) . " ({$result['type']}): " .
                                round($result['time'], 2) . " ms (Domain: {$result['domain']}, Running Avg: " .
                                round($currentAvg, 2) . " ms)\n";
                        } else {
                            Console::error("\n[FAILURE DETECTED] Test stopped on first error");
                            Console::error("Domain: {$result['domain']}");
                            Console::error("Query Type: {$result['type']}");
                            Console::error("Iteration: " . ($i + $j));
                            Console::error("Error: No records found");
                            printFailureStats($successCount, $responseTimes, $timeSeriesData);
                            cleanupTmpDir($tmpDir);
                            exit(1);
                        }
                    } else {
                        Console::error("Result file not found or timeout: {$resultFile}");
                    }
                }
            }
        }
    }

    cleanupTmpDir($tmpDir);

    if (count($responseTimes) > 0) {
        printSuccessStats($successCount, $responseTimes, $timeSeriesData, $iterations, $testCases);
    } else {
        Console::error("No successful queries. The server may not be responding.");
    }
}

function cleanupTmpDir($dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    // Try multiple times to clean up (in case files are still being written)
    $maxAttempts = 3;
    $attempt = 1;

    while ($attempt <= $maxAttempts) {
        try {
            $files = glob($dir . '/*');
            foreach ($files as $file) {
                if (is_file($file)) {
                    for ($i = 0; $i < 3; $i++) {
                        if (@unlink($file)) {
                            break;
                        }
                        usleep(100000); // Wait 100ms between attempts
                    }
                }
            }

            if (@rmdir($dir)) {
                return;
            }

            usleep(500000); // Wait 500ms before next attempt
            $attempt++;
        } catch (Throwable $e) {
            usleep(500000); // Wait 500ms before next attempt
            $attempt++;
        }
    }

    // If we couldn't clean up after all attempts, suppress the warning
    @rmdir($dir);
}

function printLatencyDistribution(array $responseTimes): void
{
    Console::info("\n--- Latency Distribution ---");
    Console::info("p50: " . round(calculatePercentile($responseTimes, 0.50), 2) . " ms");
    Console::info("p75: " . round(calculatePercentile($responseTimes, 0.75), 2) . " ms");
    Console::info("p90: " . round(calculatePercentile($responseTimes, 0.90), 2) . " ms");
    Console::info("p95: " . round(calculatePercentile($responseTimes, 0.95), 2) . " ms");
    Console::info("p99: " . round(calculatePercentile($responseTimes, 0.99), 2) . " ms");
}

function analyzeTimeSeries(array $timeSeriesData): array
{
    $windowSize = 1000; // Increased from 100 to 1000 requests per window
    $maxWindows = 10;   // Limit the number of windows we'll show
    $windows = [];

    foreach (array_chunk($timeSeriesData, $windowSize) as $index => $window) {
        // Stop if we've reached our maximum number of windows
        if ($index >= $maxWindows) {
            break;
        }

        $latencies = array_column($window, 'latency');
        $windows[] = [
            'window' => $index + 1,
            'avg' => array_sum($latencies) / count($latencies),
            'min' => min($latencies),
            'max' => max($latencies),
            'requests' => count($latencies)
        ];
    }

    return $windows;
}

function printTimeSeriesAnalysis(array $timeSeriesData): void
{
    $windows = analyzeTimeSeries($timeSeriesData);

    Console::info("\n--- Time Series Analysis (1000 requests per window) ---");
    foreach ($windows as $window) {
        Console::info(
            "Window {$window['window']} ({$window['requests']} requests): " .
            "Avg: " . round($window['avg'], 2) . "ms, " .
            "Min: " . round($window['min'], 2) . "ms, " .
            "Max: " . round($window['max'], 2) . "ms"
        );
    }
}

function printSuccessStats($successCount, $responseTimes, $timeSeriesData, $iterations, $testCases): void
{
    $min = min($responseTimes);
    $max = max($responseTimes);
    $avg = array_sum($responseTimes) / count($responseTimes);
    $totalRequests = $iterations * count($testCases) * count($testCases[array_key_first($testCases)]);

    // Calculate total test time and RPS
    $totalTime = (end($timeSeriesData)['time'] - $timeSeriesData[0]['time']) / 1000; // Convert to seconds
    $rps = $successCount / $totalTime;

    Console::success("\n--- Benchmark Results ---");
    Console::info("Total Requests: {$totalRequests}");
    Console::info("Successful: {$successCount}");
    Console::info("Failed: 0");
    Console::info("Total Test Time: " . round($totalTime, 2) . " seconds");
    Console::info("Requests Per Second: " . round($rps, 2) . " req/s");
    Console::info("\n--- Response Times ---");
    Console::info("Min Response Time: " . round($min, 2) . " ms");
    Console::info("Max Response Time: " . round($max, 2) . " ms");
    Console::info("Avg Response Time: " . round($avg, 2) . " ms");

    printLatencyDistribution($responseTimes);
    printTimeSeriesAnalysis($timeSeriesData);
}

function printFailureStats($successCount, $responseTimes, $timeSeriesData): void
{
    Console::error("\nTest Summary:");
    Console::error("- Successful queries before failure: {$successCount}");
    Console::error("- Failed at: " . date('Y-m-d H:i:s'));

    if (count($responseTimes) > 0) {
        $totalTime = (end($timeSeriesData)['time'] - $timeSeriesData[0]['time']) / 1000;
        $rps = $successCount / $totalTime;
        Console::error("- Total Test Time: " . round($totalTime, 2) . " seconds");
        Console::error("- Requests Per Second: " . round($rps, 2) . " req/s");
        Console::error("- Average response time before failure: " .
            round(array_sum($responseTimes) / count($responseTimes), 2) . " ms");
        printLatencyDistribution($responseTimes);
        printTimeSeriesAnalysis($timeSeriesData);
    }
}

// Parse command line arguments
$options = getopt('', [
    'server::',
    'port::',
    'iterations::',
    'concurrency::',
    'domains::',
    'types::'
]);

$server = $options['server'] ?? '127.0.0.1';
$port = (int)($options['port'] ?? 5300);
$iterations = (int)($options['iterations'] ?? 10000);
$concurrency = (int)($options['concurrency'] ?? 10);

// Parse domains and types
$defaultDomains = ['dev.appwrite.io', 'dev2.appwrite.io'];
$defaultTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'NS'];

$domains = isset($options['domains'])
    ? explode(',', $options['domains'])
    : $defaultDomains;

$types = isset($options['types'])
    ? explode(',', $options['types'])
    : $defaultTypes;

// Validate inputs
if ($port < 1 || $port > 65535) {
    Console::error("Invalid port number. Must be between 1 and 65535");
    exit(1);
}

if ($iterations < 1) {
    Console::error("Invalid number of iterations. Must be greater than 0");
    exit(1);
}

if ($concurrency < 1) {
    Console::error("Invalid concurrency level. Must be greater than 0");
    exit(1);
}

if ($concurrency > $iterations) {
    Console::error("Concurrency cannot be greater than iterations");
    exit(1);
}

if (empty($domains)) {
    Console::error("No domains specified for testing");
    exit(1);
}

if (empty($types)) {
    Console::error("No record types specified for testing");
    exit(1);
}

// Validate record types
$validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS', 'PTR', 'SOA'];
foreach ($types as $type) {
    if (!in_array(strtoupper($type), $validTypes)) {
        Console::error("Invalid record type: $type");
        Console::error("Valid types are: " . implode(', ', $validTypes));
        exit(1);
    }
}

// Display configuration
Console::info("DNS Server Benchmark Configuration:");
Console::info("- Server: $server");
Console::info("- Port: $port");
Console::info("- Iterations per record: $iterations");
Console::info("- Concurrency level: $concurrency");
Console::info("- Domains: " . implode(', ', $domains));
Console::info("- Record Types: " . implode(', ', $types));
Console::info("Starting benchmark in 3 seconds...\n");
sleep(3);

// Build test cases from provided domains and types
$testCases = [];
foreach ($domains as $domain) {
    $testCases[$domain] = $types;
}

benchmarkDnsServer($server, $port, $testCases, $iterations, $concurrency);
