<?php

require __DIR__ . '/../vendor/autoload.php';

use Utopia\DNS\Client;
use Utopia\CLI\Console;

function calculatePercentile(array $values, float $percentile): float 
{
    sort($values);
    $index = ceil($percentile * count($values)) - 1;
    return $values[$index];
}

function benchmarkDnsServer($server, $port, $testCases, $iterations = 100)
{
    echo "Benchmarking DNS Server: $server:$port ($iterations queries per record)...\n";

    $client = new Client($server, $port);
    $successCount = 0;
    $failedCount = 0;
    $responseTimes = [];
    $timeSeriesData = [];
    $startTime = microtime(true);

    foreach ($testCases as $domain => $queryTypes) {
        foreach ($queryTypes as $queryType) {
            for ($i = 0; $i < $iterations; $i++) {
                $start = microtime(true);
                try {
                    $records = $client->query($domain, $queryType);
                    $timeTaken = (microtime(true) - $start) * 1000; // Convert to ms
                    $elapsedTime = (microtime(true) - $startTime) * 1000;

                    if (count($records) > 0) {
                        $responseTimes[] = $timeTaken;
                        $timeSeriesData[] = [
                            'time' => $elapsedTime,
                            'latency' => $timeTaken,
                            'domain' => $domain,
                            'type' => $queryType
                        ];
                        $successCount++;
                        
                        // Calculate running statistics
                        $currentAvg = array_sum($responseTimes) / count($responseTimes);
                        echo "Query $i ($queryType): " . round($timeTaken, 2) . " ms (Domain: $domain, Running Avg: " . round($currentAvg, 2) . " ms)\n";
                    } else {
                        Console::error("\n[FAILURE DETECTED] Test stopped on first error");
                        Console::error("Domain: {$domain}");
                        Console::error("Query Type: {$queryType}");
                        Console::error("Iteration: {$i}");
                        Console::error("Error: No records found");
                        printFailureStats($successCount, $responseTimes, $timeSeriesData);
                        exit(1);
                    }
                } catch (Exception $e) {
                    Console::error("\n[FAILURE DETECTED] Test stopped on first error");
                    Console::error("Domain: {$domain}");
                    Console::error("Query Type: {$queryType}");
                    Console::error("Iteration: {$i}");
                    Console::error("Error Message: " . $e->getMessage());
                    Console::error("Stack Trace:\n" . $e->getTraceAsString());
                    printFailureStats($successCount, $responseTimes, $timeSeriesData);
                    exit(1);
                }
            }
        }
    }

    if (count($responseTimes) > 0) {
        printSuccessStats($successCount, $responseTimes, $timeSeriesData, $iterations, $testCases);
    } else {
        Console::error("No successful queries. The server may not be responding.");
    }
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
        Console::info("Window {$window['window']} ({$window['requests']} requests): " .
            "Avg: " . round($window['avg'], 2) . "ms, " .
            "Min: " . round($window['min'], 2) . "ms, " .
            "Max: " . round($window['max'], 2) . "ms"
        );
    }
}

function printFailureStats($successCount, $responseTimes, $timeSeriesData): void 
{
    Console::error("\nTest Summary:");
    Console::error("- Successful queries before failure: {$successCount}");
    Console::error("- Failed at: " . date('Y-m-d H:i:s'));
    
    if (count($responseTimes) > 0) {
        Console::error("- Average response time before failure: " . 
            round(array_sum($responseTimes) / count($responseTimes), 2) . " ms");
        printLatencyDistribution($responseTimes);
        printTimeSeriesAnalysis($timeSeriesData);
    }
}

function printSuccessStats($successCount, $responseTimes, $timeSeriesData, $iterations, $testCases): void 
{
    $min = min($responseTimes);
    $max = max($responseTimes);
    $avg = array_sum($responseTimes) / count($responseTimes);
    $totalRequests = $iterations * count($testCases) * count($testCases[array_key_first($testCases)]);
    
    Console::success("\n--- Benchmark Results ---");
    Console::info("Total Requests: {$totalRequests}");
    Console::info("Successful: {$successCount}");
    Console::info("Failed: 0");
    Console::info("Min Response Time: " . round($min, 2) . " ms");
    Console::info("Max Response Time: " . round($max, 2) . " ms");
    Console::info("Avg Response Time: " . round($avg, 2) . " ms");
    
    printLatencyDistribution($responseTimes);
    printTimeSeriesAnalysis($timeSeriesData);
}

// Define test cases with DNS record types
$testCases = [
    "dev.appwrite.io" => ["A", "AAAA", "CNAME", "TXT", "NS"],
    "dev2.appwrite.io" => ["A", "AAAA", "CNAME", "TXT", "NS"],
    "server.appwrite.io" => ["SRV"],
    "mail.appwrite.io" => ["MX"]
];

// Test Configuration
$server = "127.0.0.1"; // Your DNS server address
$port = 5300;          // Your DNS server port
$iterations = 10000;   // Queries per record

benchmarkDnsServer($server, $port, $testCases, $iterations);