import express from "express";
import path from "path";
import https from "https";
import http from "http";
import net from "net";
import crypto from "crypto";
import WebSocket from "ws";
import { createServer as createViteServer } from "vite";

const app = express();
const PORT = 3000;

app.use(express.json());

// Helper for TCP Ping
function tcpPing(ip: string, port: number, timeout: number = 1500): Promise<number> {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const socket = new net.Socket();
    
    let isFinished = false;
    const timer = setTimeout(() => {
      if (!isFinished) {
        isFinished = true;
        socket.destroy();
        reject(new Error("Timeout"));
      }
    }, timeout);
    
    socket.connect(port, ip, () => {
      if (!isFinished) {
        isFinished = true;
        clearTimeout(timer);
        const latency = Date.now() - startTime;
        socket.destroy();
        resolve(latency);
      }
    });
    
    socket.on("error", (err) => {
      if (!isFinished) {
        isFinished = true;
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      }
    });
  });
}

// Helper for HTTP/HTTPS Trace Ping
interface FullParsedConfig {
  protocol: "vless" | "vmess" | "trojan" | null;
  uuidOrPassword?: string;
  sni?: string;
  host?: string;
  path?: string;
  port?: number;
  tls?: boolean;
}

function parseFullVpnConfig(config: string): FullParsedConfig | null {
  try {
    const trimmed = config.trim();
    if (!trimmed) return null;
    
    if (trimmed.startsWith("vless://") || trimmed.startsWith("trojan://")) {
      const isVless = trimmed.startsWith("vless://");
      const protocol = isVless ? "vless" : "trojan";
      
      let urlPart = trimmed.substring(protocol.length + 3);
      const hashIdx = urlPart.indexOf("#");
      if (hashIdx !== -1) {
        urlPart = urlPart.substring(0, hashIdx);
      }
      
      const atIdx = urlPart.indexOf("@");
      if (atIdx === -1) return null;
      
      const uuidOrPassword = urlPart.substring(0, atIdx);
      const remaining = urlPart.substring(atIdx + 1);
      const qIdx = remaining.indexOf("?");
      const addrPort = qIdx !== -1 ? remaining.substring(0, qIdx) : remaining;
      const queryStr = qIdx !== -1 ? remaining.substring(qIdx + 1) : "";
      
      let parsedSni: string | undefined;
      let parsedPort = 443;
      
      const colonIdx = addrPort.lastIndexOf(":");
      if (colonIdx !== -1) {
        parsedSni = addrPort.substring(0, colonIdx);
        parsedPort = parseInt(addrPort.substring(colonIdx + 1), 10) || 443;
      } else {
        parsedSni = addrPort;
      }
      
      const searchParams = new URLSearchParams(queryStr);
      const sniParam = searchParams.get("sni") || undefined;
      const hostParam = searchParams.get("host") || undefined;
      const pathParam = searchParams.get("path") || undefined;
      const securityParam = searchParams.get("security") || undefined;
      
      const sni = sniParam || hostParam || parsedSni;
      const host = hostParam || sni;
      const path = pathParam ? decodeURIComponent(pathParam) : undefined;
      const tls = securityParam !== "none";
      
      return {
        protocol,
        uuidOrPassword,
        sni,
        host,
        path,
        port: parsedPort,
        tls
      };
    } else if (trimmed.startsWith("vmess://")) {
      const b64Str = trimmed.substring(8).trim();
      const paddedB64 = b64Str + "=".repeat((4 - (b64Str.length % 4)) % 4);
      const decoded = Buffer.from(paddedB64, "base64").toString("utf-8");
      const json_data = JSON.parse(decoded);
      
      const sni = json_data.sni || json_data.host || json_data.add;
      const host = json_data.host || json_data.add;
      const path = json_data.path;
      const port = parseInt(json_data.port, 10) || 443;
      const tls = json_data.tls === "tls";
      
      return {
        protocol: "vmess",
        uuidOrPassword: json_data.id,
        sni,
        host,
        path,
        port,
        tls
      };
    }
  } catch (err) {
    console.error("Error parsing VPN config:", err);
  }
  return null;
}

interface VpnWsResult {
  latency?: number;
  speedBytesPerSec?: number;
  bytesDownloaded?: number;
  durationMs?: number;
  error?: string;
}

function testVpnWs(
  ip: string,
  config: FullParsedConfig,
  action: "ping" | "speed",
  downloadBytes: number = 1024 * 1024, // 1MB default
  timeoutMs: number = 3000,
  testTarget: string = "cloudflare"
): Promise<VpnWsResult> {
  return new Promise((resolve) => {
    const { protocol, uuidOrPassword, sni, host, path, port, tls } = config;
    if (!protocol || (protocol !== "vless" && protocol !== "trojan")) {
      resolve({ error: "Unsupported protocol for direct tunnel scan" });
      return;
    }
    
    const targetPort = port || 443;
    const isTls = tls !== false;
    
    let wsUrl = `${isTls ? "wss" : "ws"}://${ip}:${targetPort}`;
    if (path) {
      let cleanPath = path;
      if (!cleanPath.startsWith("/")) cleanPath = "/" + cleanPath;
      wsUrl += cleanPath;
    }
    
    const wsHeaders: any = {
      "Host": host || sni || "speed.cloudflare.com",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    };
    
    const ws = new WebSocket(wsUrl, {
      headers: wsHeaders,
      servername: sni || host,
      rejectUnauthorized: false,
      handshakeTimeout: timeoutMs
    } as any);
    
    const startTime = Date.now();
    let connectedTime = 0;
    let bytesDownloaded = 0;
    let firstMessageReceived = false;
    let timeoutTimer: NodeJS.Timeout;
    
    const cleanup = () => {
      clearTimeout(timeoutTimer);
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.terminate();
      }
    };
    
    timeoutTimer = setTimeout(() => {
      cleanup();
      resolve({ error: "Timeout" });
    }, timeoutMs);
    
    ws.on("open", () => {
      connectedTime = Date.now();
      
      let headerBuf: Buffer;
      
      let targetHost = "speed.cloudflare.com";
      let destPort = 80;
      
      // For Ping, we connect to the requested target (Instagram / Google / Cloudflare)
      // For Speed, we MUST use speed.cloudflare.com because it is the only host that serves a high-speed dummy file generator.
      if (action === "ping") {
        if (testTarget === "instagram") {
          targetHost = "instagram.com";
        } else if (testTarget === "google") {
          targetHost = "www.google.com";
        }
      }
      
      const hostBuffer = Buffer.from(targetHost, "utf-8");
      
      if (protocol === "vless") {
        const uuidHex = (uuidOrPassword || "").replace(/-/g, "");
        if (uuidHex.length !== 32) {
          cleanup();
          resolve({ error: "Invalid UUID format" });
          return;
        }
        const uuidBuffer = Buffer.from(uuidHex, "hex");
        
        headerBuf = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + hostBuffer.length);
        let offset = 0;
        headerBuf.writeUInt8(0, offset++); // VLESS Version 0
        uuidBuffer.copy(headerBuf, offset); offset += 16; // UUID
        headerBuf.writeUInt8(0, offset++); // Addon length M = 0
        headerBuf.writeUInt8(1, offset++); // Command: 1 (TCP connection)
        headerBuf.writeUInt16BE(destPort, offset); offset += 2; // Port
        headerBuf.writeUInt8(2, offset++); // Address Type: 2 (Domain)
        headerBuf.writeUInt8(hostBuffer.length, offset++); // Host Length
        hostBuffer.copy(headerBuf, offset); offset += hostBuffer.length;
      } else {
        // Trojan Protocol
        const password = uuidOrPassword || "";
        const hashHex = crypto.createHash("sha224").update(password).digest("hex");
        const hashBuf = Buffer.from(hashHex, "ascii");
        
        headerBuf = Buffer.alloc(hashBuf.length + 2 + 1 + 1 + 1 + hostBuffer.length + 2 + 2);
        let offset = 0;
        hashBuf.copy(headerBuf, offset); offset += hashBuf.length; // Password SHA224 hash
        headerBuf.write("\r\n", offset, 2, "ascii"); offset += 2; // CRLF
        headerBuf.writeUInt8(1, offset++); // Command: 1 (TCP)
        headerBuf.writeUInt8(2, offset++); // Address Type: 2 (Domain)
        headerBuf.writeUInt8(hostBuffer.length, offset++); // Host Length
        hostBuffer.copy(headerBuf, offset); offset += hostBuffer.length; // Host bytes
        headerBuf.writeUInt16BE(destPort, offset); offset += 2; // Port
        headerBuf.write("\r\n", offset, 2, "ascii"); offset += 2; // CRLF
      }
      
      // Build HTTP GET Request to send inside the tunnel
      let httpRequestStr = "";
      if (action === "ping") {
        if (targetHost === "speed.cloudflare.com") {
          httpRequestStr = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
        } else {
          httpRequestStr = `GET / HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
        }
      } else {
        if (targetHost === "speed.cloudflare.com") {
          httpRequestStr = `GET /__down?bytes=${downloadBytes} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
        } else {
          httpRequestStr = `GET / HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
        }
      }
      const httpPayload = Buffer.from(httpRequestStr, "utf-8");
      const initialFrame = Buffer.concat([headerBuf, httpPayload]);
      
      ws.send(initialFrame, { binary: true }, (err) => {
        if (err) {
          cleanup();
          resolve({ error: "Failed to send handshaking payload" });
        }
      });
    });
    
    ws.on("message", (data: any, isBinary: boolean) => {
      if (!isBinary) return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      
      let payload = buf;
      if (!firstMessageReceived) {
        firstMessageReceived = true;
        
        if (protocol === "vless") {
          // VLESS response header: Version (1 byte), Addons length M (1 byte), Addons (M bytes)
          if (buf.length >= 2) {
            const addonLen = buf.readUInt8(1);
            if (buf.length >= 2 + addonLen) {
              payload = buf.subarray(2 + addonLen);
            }
          }
        }
        
        if (action === "ping") {
          const latency = Date.now() - startTime;
          cleanup();
          resolve({ latency });
          return;
        }
      }
      
      bytesDownloaded += payload.length;
      
      if (action === "speed") {
        const elapsed = (Date.now() - connectedTime) / 1000;
        if (bytesDownloaded >= downloadBytes || elapsed >= (timeoutMs / 1000)) {
          const durationMs = Math.max(10, Date.now() - connectedTime);
          const speedBytesPerSec = bytesDownloaded / (durationMs / 1000);
          cleanup();
          resolve({ speedBytesPerSec, bytesDownloaded, durationMs });
        }
      }
    });
    
    ws.on("error", (err) => {
      cleanup();
      resolve({ error: err.message || "WS Connection Error" });
    });
    
    ws.on("close", () => {
      cleanup();
      if (action === "speed" && bytesDownloaded > 1024) {
        const durationMs = Math.max(10, Date.now() - connectedTime);
        const speedBytesPerSec = bytesDownloaded / (durationMs / 1000);
        resolve({ speedBytesPerSec, bytesDownloaded, durationMs });
      } else if (action === "ping" && firstMessageReceived) {
        const latency = Date.now() - startTime;
        resolve({ latency });
      } else {
        resolve({ error: "Closed before receiving valid data" });
      }
    });
  });
}

// Helper for HTTP/HTTPS Trace Ping
function httpPing(
  ip: string,
  port: number,
  timeout: number = 2000,
  tls: boolean = true,
  hostHeader?: string,
  customPath?: string,
  sni?: string
): Promise<number> {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const requestModule = tls ? https : http;
    
    const options: any = {
      hostname: ip,
      port: port,
      path: customPath || "/cdn-cgi/trace",
      method: "GET",
      rejectUnauthorized: false,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      }
    };
    
    const targetHost = hostHeader || "speed.cloudflare.com";
    options.headers["Host"] = targetHost;
    if (tls) {
      options.servername = sni || targetHost; // Sets TLS SNI
    }
    
    let isFinished = false;
    const timer = setTimeout(() => {
      if (!isFinished) {
        isFinished = true;
        req.destroy();
        reject(new Error("Timeout"));
      }
    }, timeout);
    
    const req = requestModule.request(options, (res) => {
      res.on("data", () => {}); // Consume response
      res.on("end", () => {
        if (!isFinished) {
          isFinished = true;
          clearTimeout(timer);
          const latency = Date.now() - startTime;
          resolve(latency);
        }
      });
    });
    
    req.on("error", (err) => {
      if (!isFinished) {
        isFinished = true;
        clearTimeout(timer);
        reject(err);
      }
    });
    
    req.end();
  });
}

// Helper for Speed Test
function testSpeed(
  ip: string,
  port: number,
  tls: boolean = true,
  hostHeader?: string,
  downloadBytes: number = 1572864, // 1.5MB default
  timeout: number = 8000,
  customUrl?: string,
  sni?: string,
  customPath?: string
): Promise<{ speedBytesPerSec: number; bytesDownloaded: number; durationMs: number }> {
  return new Promise((resolve, reject) => {
    let isTls = tls;
    let targetPort = port;
    let targetPath = customPath || `/__down?bytes=${downloadBytes}`;
    let targetHost = hostHeader || "speed.cloudflare.com";
    let byteLimit = downloadBytes;

    if (customUrl) {
      try {
        const parsed = new URL(customUrl);
        isTls = parsed.protocol === "https:";
        targetHost = parsed.hostname;
        targetPort = parsed.port ? Number(parsed.port) : (isTls ? 443 : 80);
        targetPath = parsed.pathname + parsed.search;
        // Limit custom downloads to 3MB max to prevent huge data use during speed testing
        byteLimit = Math.min(downloadBytes, 3 * 1048576);
      } catch (e: any) {
        reject(new Error("Invalid custom URL: " + e.message));
        return;
      }
    }

    const requestModule = isTls ? https : http;
    
    const options: any = {
      hostname: ip,
      port: targetPort,
      path: targetPath,
      method: "GET",
      timeout: timeout,
      rejectUnauthorized: false,
      headers: {
        "Host": targetHost,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Encoding": "identity" // Ensure raw bytes are received
      }
    };
    
    if (isTls) {
      options.servername = sni || targetHost;
    }
    
    let bytesDownloaded = 0;
    const requestStartTime = Date.now();
    let isFinished = false;

    const cleanupAndResolve = () => {
      if (isFinished) return;
      isFinished = true;
      const durationMs = Date.now() - requestStartTime;
      const durationSec = durationMs / 1000;
      const speedBytesPerSec = bytesDownloaded / (durationSec || 0.1);
      resolve({
        speedBytesPerSec,
        bytesDownloaded,
        durationMs
      });
    };
    
    const req = requestModule.request(options, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        reject(new Error(`HTTP Status ${res.statusCode}`));
        return;
      }
      
      // Limit speed test to maximum timeout per IP
      const speedTimeout = setTimeout(() => {
        req.destroy();
        cleanupAndResolve();
      }, timeout);

      res.on("data", (chunk) => {
        bytesDownloaded += chunk.length;
        if (bytesDownloaded >= byteLimit) {
          clearTimeout(speedTimeout);
          req.destroy();
          cleanupAndResolve();
        }
      });
      
      res.on("end", () => {
        clearTimeout(speedTimeout);
        cleanupAndResolve();
      });
    });
    
    req.on("error", (err) => {
      if (!isFinished) {
        reject(err);
      }
    });
    
    req.on("timeout", () => {
      req.destroy();
      if (!isFinished) {
        reject(new Error("Timeout"));
      }
    });
    
    req.end();
  });
}

// API Route: Ping Batch of IPs (with Concurrency Control)
app.post("/api/scan/ping", async (req, res) => {
  const { ips, port, timeout, tls, hostHeader, customPath, testType, baseConfigUrl, testTarget, pingCount: reqPingCount, concurrencyLimit: reqConcurrencyLimit } = req.body;
  
  if (!Array.isArray(ips) || ips.length === 0) {
    res.status(400).json({ error: "Invalid or empty IP list" });
    return;
  }
  
  const pingCount = Math.min(Math.max(Number(reqPingCount) || 1, 1), 10);
  const concurrencyLimit = Math.min(Math.max(Number(reqConcurrencyLimit) || 10, 1), 50);
  
  let configPort = Number(port) || 443;
  let configTls = tls !== false;
  let configHost = hostHeader || "speed.cloudflare.com";
  let configPath = customPath || "/cdn-cgi/trace";
  let configSni: string | undefined = undefined;

  let parsedConfig: FullParsedConfig | null = null;
  if (baseConfigUrl) {
    parsedConfig = parseFullVpnConfig(baseConfigUrl);
    if (parsedConfig) {
      if (parsedConfig.port) configPort = parsedConfig.port;
      if (parsedConfig.tls !== undefined) configTls = parsedConfig.tls;
      if (parsedConfig.host) configHost = parsedConfig.host;
      if (parsedConfig.path) {
        configPath = parsedConfig.path;
        if (!configPath.startsWith("/")) {
          configPath = "/" + configPath;
        }
      } else {
        configPath = "/cdn-cgi/trace";
      }
      if (parsedConfig.sni) configSni = parsedConfig.sni;
    }
  }

  const targetPort = configPort;
  const targetTimeout = Number(timeout) || 1500;
  const isTls = configTls;
  const targetTestType = testType || "tcp"; // "tcp" or "http"
  
  // Controlled concurrency scanning
  const results: Array<{ 
    ip: string; 
    latency?: number; 
    success: boolean; 
    error?: string;
    pingHistory?: number[];
    packetLoss?: number;
    jitter?: number;
    minLatency?: number;
    maxLatency?: number;
    pingCount?: number;
  }> = [];
  
  let index = 0;
  async function worker() {
    while (index < ips.length) {
      const currentIndex = index++;
      const ip = ips[currentIndex];
      
      const latencies: number[] = [];
      let successCount = 0;
      let failureCount = 0;
      let lastError = "";
      
      for (let c = 0; c < pingCount; c++) {
        if (c > 0) {
          // Small delay between pings to avoid overloading the socket and to measure real interval variation
          await new Promise(resolve => setTimeout(resolve, 80));
        }
        
        try {
          let lat: number;
          if (parsedConfig && (parsedConfig.protocol === "vless" || parsedConfig.protocol === "trojan")) {
            try {
              const wsResult = await testVpnWs(ip, parsedConfig, "ping", 0, targetTimeout, testTarget);
              if (wsResult.latency !== undefined) {
                lat = wsResult.latency;
              } else {
                throw new Error(wsResult.error || "Tunnel connection failed");
              }
            } catch (wsErr) {
              if (targetTestType === "tcp") {
                lat = await tcpPing(ip, targetPort, targetTimeout);
              } else {
                lat = await httpPing(ip, targetPort, targetTimeout, isTls, configHost, configPath, configSni);
              }
            }
          } else {
            if (targetTestType === "tcp") {
              lat = await tcpPing(ip, targetPort, targetTimeout);
            } else {
              lat = await httpPing(ip, targetPort, targetTimeout, isTls, configHost, configPath, configSni);
            }
          }
          latencies.push(lat);
          successCount++;
        } catch (err: any) {
          failureCount++;
          lastError = err.message || "Failed";
        }
      }
      
      if (successCount > 0) {
        const avgLatency = Math.round(latencies.reduce((a, b) => a + b, 0) / successCount);
        const packetLoss = Math.round((failureCount / pingCount) * 100);
        const minLatency = Math.min(...latencies);
        const maxLatency = Math.max(...latencies);
        const jitter = maxLatency - minLatency;
        
        results[currentIndex] = {
          ip,
          latency: avgLatency,
          success: true,
          pingHistory: latencies,
          packetLoss,
          jitter,
          minLatency,
          maxLatency,
          pingCount
        };
      } else {
        results[currentIndex] = {
          ip,
          success: false,
          error: lastError || "Failed",
          packetLoss: 100,
          pingCount
        };
      }
    }
  }
  
  const workers = Array.from({ length: Math.min(concurrencyLimit, ips.length) }, worker);
  await Promise.all(workers);
  
  res.json({ results });
});

// API Route: Test Speed for a Single IP
app.post("/api/scan/speed", async (req, res) => {
  const { ip, port, tls, hostHeader, downloadSizeMb, downloadTimeoutSec, customUrl, baseConfigUrl, testTarget } = req.body;
  
  if (!ip) {
    res.status(400).json({ error: "IP address is required" });
    return;
  }
  
  let configPort = Number(port) || 443;
  let configTls = tls !== false;
  let configHost = hostHeader || "speed.cloudflare.com";
  let configPath: string | undefined = undefined;
  let configSni: string | undefined = undefined;
  
  let parsedConfig: FullParsedConfig | null = null;
  if (baseConfigUrl) {
    parsedConfig = parseFullVpnConfig(baseConfigUrl);
    if (parsedConfig) {
      if (parsedConfig.port) configPort = parsedConfig.port;
      if (parsedConfig.tls !== undefined) configTls = parsedConfig.tls;
      if (parsedConfig.host) configHost = parsedConfig.host;
      if (parsedConfig.path) {
        configPath = parsedConfig.path;
        if (!configPath.startsWith("/")) {
          configPath = "/" + configPath;
        }
      }
      if (parsedConfig.sni) configSni = parsedConfig.sni;
    }
  }

  const targetPort = configPort;
  const isTls = configTls;
  // Convert MB to bytes (1MB = 1048576 bytes)
  const sizeMb = Number(downloadSizeMb) || 1.5;
  const downloadBytes = Math.round(sizeMb * 1048576);
  
  const timeoutSec = Number(downloadTimeoutSec) || 8;
  const timeoutMs = timeoutSec * 1000;
  
  try {
    let result;
    let fallbackUsed = false;
    let originalError = "";

    // Direct Tunnel Speed Test for VLESS and Trojan over WS
    if (parsedConfig && (parsedConfig.protocol === "vless" || parsedConfig.protocol === "trojan")) {
      try {
        const wsResult = await testVpnWs(ip, parsedConfig, "speed", downloadBytes, timeoutMs, testTarget);
        if (wsResult.speedBytesPerSec !== undefined) {
          result = {
            speedBytesPerSec: wsResult.speedBytesPerSec,
            bytesDownloaded: wsResult.bytesDownloaded || 0,
            durationMs: wsResult.durationMs || 0
          };
        } else {
          throw new Error(wsResult.error || "Tunnel speed test failed");
        }
      } catch (err: any) {
        originalError = err.message || "Tunnel speed test failed";
        // Fallback to standard Cloudflare speed test on the same IP
        result = await testSpeed(ip, 443, true, "speed.cloudflare.com", downloadBytes, timeoutMs);
        fallbackUsed = true;
      }
    } else if (customUrl) {
      try {
        result = await testSpeed(ip, targetPort, isTls, configHost, downloadBytes, timeoutMs, customUrl, configSni);
      } catch (err: any) {
        originalError = err.message || "Custom URL speed test failed";
        // Fallback to standard Cloudflare speed test on the same IP
        result = await testSpeed(ip, 443, true, "speed.cloudflare.com", downloadBytes, timeoutMs);
        fallbackUsed = true;
      }
    } else {
      result = await testSpeed(ip, targetPort, isTls, configHost, downloadBytes, timeoutMs, undefined, configSni, configPath);
    }

    const speedMbps = (result.speedBytesPerSec * 8) / 1000000;
    const speedMbPerSec = result.speedBytesPerSec / 1000000;
    
    res.json({
      success: true,
      ip,
      speedMbps: Number(speedMbps.toFixed(2)),
      speedMbPerSec: Number(speedMbPerSec.toFixed(2)),
      bytesDownloaded: result.bytesDownloaded,
      durationMs: result.durationMs,
      fallbackUsed,
      originalError: fallbackUsed ? originalError : undefined
    });
  } catch (err: any) {
    res.status(500).json({
      success: false,
      ip,
      error: err.message || "Speed test failed"
    });
  }
});

// API Route: Fetch Inbounds from 3x-ui Panel
app.post("/api/3x-ui/inbounds", async (req, res) => {
  const { panelUrl, username, password, sessionCookie, apiToken } = req.body;

  if (!panelUrl || (!sessionCookie && !apiToken && (!username || !password))) {
    res.status(400).json({ error: "Missing required fields for authentication" });
    return;
  }

  try {
    let cleanUrl = panelUrl.trim();
    if (cleanUrl.endsWith("/")) {
      cleanUrl = cleanUrl.slice(0, -1);
    }

    let cookieString = "";
    let isBearerAuth = false;

    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    if (apiToken && apiToken.trim()) {
      isBearerAuth = true;
    } else if (sessionCookie && sessionCookie.trim()) {
      const trimmed = sessionCookie.trim();
      cookieString = trimmed.includes("=") ? trimmed : `session=${trimmed}`;
    } else {
      let initCookies = "";
      try {
        const getResponse = await fetch(`${cleanUrl}/login`, {
          method: "GET",
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
          }
        });
        const rawGetCookieHeader = getResponse.headers.get("set-cookie");
        const getCookieHeaders = typeof getResponse.headers.getSetCookie === "function"
          ? getResponse.headers.getSetCookie()
          : (rawGetCookieHeader ? [rawGetCookieHeader] : []);
        if (getCookieHeaders.length > 0) {
          initCookies = getCookieHeaders.map(c => c.split(";")[0]).join("; ");
        }
      } catch (e) {}

      let origin = "";
      try {
        origin = new URL(cleanUrl).origin;
      } catch (e) {}

      const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "fa,fa-IR;q=0.9,en-US;q=0.8,en;q=0.7"
      };

      const loginAttempts = [
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          getBody: () => {
            const params = new URLSearchParams();
            params.append("username", username || "");
            params.append("password", password || "");
            return params;
          }
        },
        {
          headers: { "Content-Type": "application/json" },
          getBody: () => JSON.stringify({ username, password })
        }
      ];

      let loginResponse = null;
      for (const attempt of loginAttempts) {
        try {
          const attemptHeaders = { ...headers, ...attempt.headers };
          if (origin) {
            attemptHeaders["Origin"] = origin;
            attemptHeaders["Referer"] = `${cleanUrl}/login`;
          }
          if (initCookies) {
            attemptHeaders["Cookie"] = initCookies;
          }
          const resObj = await fetch(`${cleanUrl}/login`, {
            method: "POST",
            headers: attemptHeaders,
            body: attempt.getBody() as any,
            redirect: "manual"
          });
          if (resObj.status === 200 || resObj.status === 302) {
            loginResponse = resObj;
            break;
          }
        } catch (e) {}
      }

      if (!loginResponse) {
        res.status(401).json({ error: "Failed to authenticate with panel during inbounds check" });
        return;
      }

      const rawCookieHeader = loginResponse.headers.get("set-cookie");
      const setCookieHeaders = typeof loginResponse.headers.getSetCookie === "function"
        ? loginResponse.headers.getSetCookie()
        : (rawCookieHeader ? [rawCookieHeader] : []);

      if (setCookieHeaders.length > 0) {
        cookieString = setCookieHeaders.map(c => c.split(";")[0]).join("; ");
      } else if (initCookies) {
        cookieString = initCookies;
      } else {
        res.status(401).json({ error: "No session cookie returned during inbounds check" });
        return;
      }
    }

    const inboundsPaths = [
      "/panel/api/inbounds/list",
      "/xui/API/inbounds/list",
      "/xui/api/inbounds/list",
      "/api/inbounds/list"
    ];

    const requestHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "X-Requested-With": "XMLHttpRequest"
    };
    if (isBearerAuth) {
      requestHeaders["Authorization"] = `Bearer ${apiToken.trim()}`;
    } else {
      requestHeaders["Cookie"] = cookieString;
    }

    let inboundsData = null;
    let successfulPath = "";

    for (const path of inboundsPaths) {
      let finalUrl = `${cleanUrl}${path}`;
      try {
        const parsedClean = new URL(cleanUrl);
        const basePath = parsedClean.pathname;
        if (basePath && basePath !== "/" && path.startsWith(basePath)) {
          finalUrl = `${parsedClean.origin}${path}`;
        }
      } catch (e) {}

      try {
        const response = await fetch(finalUrl, {
          method: "GET",
          headers: requestHeaders
        });

        if (response.status === 200) {
          const text = await response.text();
          if (!text.trim().startsWith("<")) {
            const json = JSON.parse(text);
            if (json && json.success) {
              inboundsData = json;
              successfulPath = path;
              break;
            }
          }
        }
      } catch (e) {}
    }

    if (!inboundsData) {
      res.status(404).json({ error: "Could not fetch inbounds list from your panel. Please check your URL and permissions." });
      return;
    }

    const list = Array.isArray(inboundsData.obj) ? inboundsData.obj : [];
    const inbounds = list.map((item: any) => ({
      id: item.id,
      tag: item.tag,
      port: item.port,
      protocol: item.protocol,
      remark: item.remark,
      enable: item.enable
    }));

    res.json({
      success: true,
      inbounds,
      path: successfulPath
    });

  } catch (err: any) {
    res.status(500).json({ error: err.message || "Failed to retrieve inbounds" });
  }
});

// API Route: Sync Hosts to 3x-ui Panel
app.post("/api/3x-ui/sync-hosts", async (req, res) => {
  const { panelUrl, username, password, sessionCookie, apiToken, hosts } = req.body;

  if (!panelUrl || (!sessionCookie && !apiToken && (!username || !password)) || !Array.isArray(hosts) || hosts.length === 0) {
    res.status(400).json({ error: "Missing required fields (Panel URL and either Session Cookie, API Token, or Username/Password) or empty hosts list" });
    return;
  }

  try {
    // 1. Clean panel URL (remove trailing slash)
    let cleanUrl = panelUrl.trim();
    if (cleanUrl.endsWith("/")) {
      cleanUrl = cleanUrl.slice(0, -1);
    }

    let cookieString = "";
    let isBearerAuth = false;

    // Set environment variable to bypass self-signed certificate rejection
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    // If the user provided an API Token, we use it directly and bypass login completely!
    if (apiToken && apiToken.trim()) {
      isBearerAuth = true;
      console.log("Using API Token (Bearer Auth). Bypassing login phase.");
    } else if (sessionCookie && sessionCookie.trim()) {
      const trimmed = sessionCookie.trim();
      cookieString = trimmed.includes("=") ? trimmed : `session=${trimmed}`;
      console.log("Using user-provided direct session cookie. Bypassing login phase.");
    } else {
      // 2. Login to 3x-ui panel
      // First, do a GET request to /login to establish session/cookies if required by reverse proxies or security modules
      let initCookies = "";
      try {
        const getController = new AbortController();
        const getTimeout = setTimeout(() => getController.abort(), 6000);
        
        const getResponse = await fetch(`${cleanUrl}/login`, {
          method: "GET",
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "fa,fa-IR;q=0.9,en-US;q=0.8,en;q=0.7"
          },
          signal: getController.signal
        });

        const rawGetCookieHeader = getResponse.headers.get("set-cookie");
        const getCookieHeaders = typeof getResponse.headers.getSetCookie === "function"
          ? getResponse.headers.getSetCookie()
          : (rawGetCookieHeader ? [rawGetCookieHeader] : []);
          
        if (getCookieHeaders.length > 0) {
          initCookies = getCookieHeaders.map(c => c.split(";")[0]).join("; ");
        }
        clearTimeout(getTimeout);
      } catch (e) {
        // Ignore initial GET failure and try to proceed with POST
      }

      // Extract origin and referer to bypass simple security policies & reverse proxies
      let origin = "";
      try {
        const parsedUrl = new URL(cleanUrl);
        origin = parsedUrl.origin;
      } catch (e) {
        // fallback
      }

      const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "fa,fa-IR;q=0.9,en-US;q=0.8,en;q=0.7"
      };

      let loginResponse: any = null;
      let lastLoginError: any = null;

      // We will try 3 methods in sequence to log in:
      // Method 1: Standard URL-Encoded Form Post (no X-Requested-With, mimicking a real browser form submit)
      // Method 2: AJAX URL-Encoded Form Post (with X-Requested-With: XMLHttpRequest)
      // Method 3: JSON Payload ({"username": "...", "password": "..."})

      const loginAttempts = [
        {
          name: "Standard URL-Encoded Form",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
          },
          getBody: () => {
            const params = new URLSearchParams();
            params.append("username", username || "");
            params.append("password", password || "");
            return params;
          }
        },
        {
          name: "AJAX URL-Encoded Form",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest"
          },
          getBody: () => {
            const params = new URLSearchParams();
            params.append("username", username || "");
            params.append("password", password || "");
            return params;
          }
        },
        {
          name: "JSON Payload",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*"
          },
          getBody: () => JSON.stringify({ username, password })
        }
      ];

      for (let i = 0; i < loginAttempts.length; i++) {
        const attempt = loginAttempts[i];
        const attemptHeaders: Record<string, string> = { ...headers, ...attempt.headers };
        
        if (origin) {
          attemptHeaders["Origin"] = origin;
          attemptHeaders["Referer"] = `${cleanUrl}/login`;
        }
        if (initCookies) {
          attemptHeaders["Cookie"] = initCookies;
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000); // 10 seconds per attempt

        try {
          console.log(`Attempting login method ${i + 1}/${loginAttempts.length}: ${attempt.name}`);
          const resObj = await fetch(`${cleanUrl}/login`, {
            method: "POST",
            headers: attemptHeaders,
            body: attempt.getBody() as any,
            redirect: "manual",
            signal: controller.signal
          });

          clearTimeout(timeout);

          if (resObj.status === 200 || resObj.status === 302) {
            console.log(`Login method ${attempt.name} succeeded with status ${resObj.status}!`);
            loginResponse = resObj;
            break;
          } else {
            console.log(`Login method ${attempt.name} returned status ${resObj.status}`);
            loginResponse = resObj; // Keep reference to last response
          }
        } catch (err: any) {
          clearTimeout(timeout);
          lastLoginError = err;
          console.log(`Login method ${attempt.name} failed with error:`, err.message || err);
          if (err.name === "AbortError" || err.message?.includes("aborted")) {
            // timed out, continue to next method
          }
        }
      }

      if (!loginResponse) {
        const errMessage = lastLoginError?.message || "Connection failed";
        res.status(502).json({
          error: `Failed to connect to the panel. Please make sure the IP and port are reachable from the outside.\n\n` +
                 `خطا در برقراری ارتباط با پنل. لطفاً مطمئن شوید سرور روشن است و پورت پنل روی اینترنت باز می‌باشد.\n\n` +
                 `Details: ${errMessage}`
        });
        return;
      }

      // Check status
      if (loginResponse.status !== 200 && loginResponse.status !== 302) {
        const errorText = await loginResponse.text().catch(() => "");
        console.log(`Login failed with status ${loginResponse.status}, response:`, errorText);
        
        let friendlyMessage = `Login failed with status ${loginResponse.status}`;
        
        const isCloudflare = errorText.includes("cloudflare") || errorText.includes("Cloudflare") || errorText.includes("cf-challenge") || errorText.includes("cf-ray");
        const cleanPathPart = panelUrl.replace(/^https?:\/\//i, ""); // e.g., "1.2.3.4:2053" or "1.2.3.4:2053/path"
        const hasPath = cleanPathPart.includes("/") && cleanPathPart.substring(cleanPathPart.indexOf("/") + 1).trim().length > 0;

        if (loginResponse.status === 403) {
          if (isCloudflare) {
            friendlyMessage = "Forbidden (403): Your 3x-ui panel is behind Cloudflare, and the request was blocked by Cloudflare's Security/WAF. Please disable Cloudflare proxy (set DNS status to 'DNS Only' / gray cloud) or allow Google Cloud IPs in WAF.\n\n" +
                              "خطای دسترسی (403): پنل شما پشت کلادفلر قرار دارد و درخواست توسط دیوار آتش (WAF) کلادفلر مسدود شده است. لطفاً پروکسی کلادفلر زیردامنه خود را غیرفعال کنید (روی حالت خاکستری یا DNS Only قرار دهید) یا آی‌پی‌های گوگل کلود را در فایروال کلادفلر مجاز کنید.";
          } else if (!hasPath) {
            friendlyMessage = "Forbidden (403): Access denied. If your panel has a custom path (Web Base Path) configured in settings, you MUST include it in the URL (e.g., http://your-ip:port/custom-path).\n\n" +
                              "خطای دسترسی (403): دسترسی مسدود شد. اگر پنل شما دارای «مسیر اختصاصی» (Web Base Path) در تنظیمات است، حتماً باید آن را در انتهای آدرس وارد کنید (مثال: http://your-ip:port/custom-path).";
          } else {
            friendlyMessage = "Forbidden (403): Access denied. This is typically caused by: 1) Wrong custom Web Base Path in the URL. 2) A firewall/fail2ban on your server blocking our backend IP. 3) Wrong credentials too many times causing a temp ban.\n\n" +
                              "خطای دسترسی (403): دسترسی مسدود شد. این خطا معمولاً به دلایل زیر رخ می‌دهد: ۱) اشتباه بودن مسیر اختصاصی (Web Base Path) وارد شده در آدرس. ۲) فایروال یا سیستم امنیتی سرور شما آی‌پی‌های سرور اسکنر را مسدود کرده است. ۳) ورود مکرر اطلاعات اشتباه و مسدود شدن موقت آی‌پی شما توسط پنل.";
          }
        } else if (loginResponse.status === 404) {
          friendlyMessage = `Not Found (404): The login page was not found at ${cleanUrl}/login. Please double-check your Panel URL and ensure your Web Base Path is correct.\n\n` +
                            `خطای یافت نشد (404): صفحه ورود در این آدرس پیدا نشد. لطفاً آدرس پنل و صحت مسیر اختصاصی (Web Base Path) خود را بررسی کنید.`;
        } else if (loginResponse.status === 502 || loginResponse.status === 504) {
          friendlyMessage = `Bad Gateway / Gateway Timeout (${loginResponse.status}): Your panel server is unreachable, offline, or blocking requests.\n\n` +
                            `خطای دروازه (۵۰۲/۵۰۴): سرور پنل شما در دسترس نیست، خاموش است یا ارتباط را مسدود کرده است.`;
        } else {
          friendlyMessage = `Login failed with status ${loginResponse.status}. Please make sure your server is online, URL is correct, and port is open.\n\n` +
                            `خطا در ورود به پنل با وضعیت ${loginResponse.status}. لطفا مطمئن شوید سرور روشن است، آدرس دقیق است و پورت پنل باز می‌باشد.`;
        }

        // Add actual server response snippet if available to help users debug
        const snippet = errorText.trim().replace(/<[^>]*>/g, "").slice(0, 200).trim();
        if (snippet) {
          friendlyMessage += `\n\n[Server Response Snippet / خلاصه پاسخ سرور]:\n${snippet}`;
        }

        res.status(loginResponse.status || 401).json({ error: friendlyMessage });
        return;
      }

      // Extract cookies safely
      const rawCookieHeader = loginResponse.headers.get("set-cookie");
      const setCookieHeaders = typeof loginResponse.headers.getSetCookie === "function" 
        ? loginResponse.headers.getSetCookie() 
        : (rawCookieHeader ? [rawCookieHeader] : []);

      if (setCookieHeaders.length > 0) {
        cookieString = setCookieHeaders.map(c => c.split(";")[0]).join("; ");
      } else if (initCookies) {
        console.log("No new set-cookie header returned, reusing established session cookie from initial GET.");
        cookieString = initCookies;
      } else {
        res.status(401).json({ 
          error: "No session cookie returned from 3x-ui panel.\n\n" +
                 "هیچ کوکی نشست (Session Cookie) از پنل دریافت نشد. این موضوع می‌تواند به خاطر اطلاعات ورود نامعتبر یا ناسازگاری موقت با سرور رخ دهد." 
        });
        return;
      }
    }

    // 3. Register each host
    const results = [];
    let successCount = 0;
    let failCount = 0;

    // We try to find the correct endpoint path. Let's try multiple common paths if one fails with 404
    let possiblePaths = [
      "/panel/api/hosts/add",
      "/panel/api/hosts/addHost",
      "/panel/api/hosts/add_host",
      "/panel/api/hosts/add-host",
      "/panel/api/hosts/addhost",
      "/api/hosts/add",
      "/api/hosts/addHost",
      "/api/hosts/add_host",
      "/api/hosts/addhost",
      "/xui/API/hosts/add",
      "/xui/api/hosts/add",
      "/xui/api/hosts/addHost",
      
      "/panel/api/routing/addHost",
      "/panel/api/routing/add_host",
      "/panel/api/routing/add-host",
      "/panel/api/routing/addhost",
      "/xui/API/routing/addHost",
      "/xui/api/routing/addHost",
      "/api/routing/addHost"
    ];

    // Dynamically query OpenAPI if possible to find the correct endpoints!
    try {
      const openApiHeaders: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "X-Requested-With": "XMLHttpRequest"
      };
      if (isBearerAuth) {
        openApiHeaders["Authorization"] = `Bearer ${apiToken.trim()}`;
      } else {
        openApiHeaders["Cookie"] = cookieString;
      }

      console.log(`Checking OpenAPI endpoint at ${cleanUrl}/panel/api/openapi.json to discover routing/hosts paths...`);
      const openApiResponse = await fetch(`${cleanUrl}/panel/api/openapi.json`, {
        method: "GET",
        headers: openApiHeaders
      });

      if (openApiResponse.status === 200) {
        const openApiText = await openApiResponse.text();
        const isOpenApiHtml = openApiText.trim().startsWith("<") || openApiText.toLowerCase().includes("<html");
        
        if (isOpenApiHtml) {
          console.log("OpenAPI discovery returned HTML (likely redirected or unauthorized). Skipping.");
        } else {
          try {
            const openApiData = JSON.parse(openApiText);
            if (openApiData && openApiData.paths) {
              const apiPaths = Object.keys(openApiData.paths);
              console.log("Discovered panel API paths:", apiPaths);
              
              // Filter any path containing 'routing/addHost' or 'hosts/add' or 'host'
              const discoveredHostsPaths = apiPaths.filter(p => 
                p.toLowerCase().includes("host") || p.toLowerCase().includes("routing")
              );
              
              if (discoveredHostsPaths.length > 0) {
                console.log("Discovered potential host/routing paths in OpenAPI:", discoveredHostsPaths);
                possiblePaths = [...discoveredHostsPaths, ...possiblePaths];
              }
            }
          } catch (jsonErr: any) {
            console.log("Failed to parse OpenAPI JSON:", jsonErr.message || jsonErr);
          }
        }
      } else {
        console.log(`OpenAPI check returned status ${openApiResponse.status}`);
      }
    } catch (openApiErr: any) {
      console.log("Failed to inspect OpenAPI endpoint:", openApiErr.message || openApiErr);
    }

    // Deduplicate possiblePaths while maintaining order
    possiblePaths = Array.from(new Set(possiblePaths));

    let workingPath = possiblePaths[0];

    // Let's pre-fetch the list of inbounds so we can map host.inbound (tag/name/id) to a numeric inboundId
    let discoveredInbounds: any[] = [];
    try {
      const inboundsPaths = [
        "/panel/api/inbounds/list",
        "/xui/API/inbounds/list",
        "/xui/api/inbounds/list",
        "/api/inbounds/list"
      ];
      const checkHeaders: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "X-Requested-With": "XMLHttpRequest"
      };
      if (isBearerAuth) {
        checkHeaders["Authorization"] = `Bearer ${apiToken.trim()}`;
      } else {
        checkHeaders["Cookie"] = cookieString;
      }

      for (const path of inboundsPaths) {
        let finalUrl = `${cleanUrl}${path}`;
        try {
          const parsedClean = new URL(cleanUrl);
          const basePath = parsedClean.pathname;
          if (basePath && basePath !== "/" && path.startsWith(basePath)) {
            finalUrl = `${parsedClean.origin}${path}`;
          }
        } catch (e) {}

        try {
          const checkResponse = await fetch(finalUrl, {
            method: "GET",
            headers: checkHeaders
          });
          if (checkResponse.status === 200) {
            const checkText = await checkResponse.text();
            if (!checkText.trim().startsWith("<")) {
              const checkJson = JSON.parse(checkText);
              if (checkJson && checkJson.success && Array.isArray(checkJson.obj)) {
                discoveredInbounds = checkJson.obj;
                console.log(`Fetched ${discoveredInbounds.length} inbounds successfully inside sync-hosts for mapping.`);
                break;
              }
            }
          }
        } catch (e) {}
      }
    } catch (e: any) {
      console.log("Failed to pre-fetch inbounds for mapping:", e.message || e);
    }

    for (const host of hosts) {
      let hostSynced = false;
      let lastError = "";
      const pathDiagnostics = [];

      // Resolve inboundId (crucial for 3x-ui /hosts/add endpoint!)
      let inboundId: number | undefined = undefined;
      
      // If the frontend already passed host.inboundId, use it!
      if (host.inboundId !== undefined && host.inboundId !== null && host.inboundId !== "") {
        inboundId = Number(host.inboundId);
      }
      
      const searchTarget = (host.inbound || "").toString().trim();
      
      // If we don't have inboundId yet, try to find it in the discoveredInbounds
      if (inboundId === undefined && searchTarget && discoveredInbounds.length > 0) {
        let matched = discoveredInbounds.find(inb => inb.tag && inb.tag.toString().trim() === searchTarget);
        if (!matched) {
          matched = discoveredInbounds.find(inb => inb.id && inb.id.toString().trim() === searchTarget);
        }
        if (!matched) {
          matched = discoveredInbounds.find(inb => inb.tag && inb.tag.toString().trim().toLowerCase() === searchTarget.toLowerCase());
        }
        if (matched) {
          inboundId = Number(matched.id);
          console.log(`Mapped inbound "${searchTarget}" to inboundId ${inboundId}`);
        }
      }

      // Fallback: if we still don't have it, and searchTarget is a number, parse it
      if (inboundId === undefined && /^\d+$/.test(searchTarget)) {
        inboundId = Number(searchTarget);
      }

      // Try possible paths in sequence
      for (const path of possiblePaths) {
        let addResponse;
        const addController = new AbortController();
        const addTimeout = setTimeout(() => addController.abort(), 8000); // 8 seconds per path try

        try {
          const requestHeaders: Record<string, string> = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "X-Requested-With": "XMLHttpRequest"
          };

          if (isBearerAuth) {
            requestHeaders["Authorization"] = `Bearer ${apiToken.trim()}`;
          } else {
            requestHeaders["Cookie"] = cookieString;
          }

          let finalUrl = `${cleanUrl}${path}`;
          try {
            const parsedClean = new URL(cleanUrl);
            const basePath = parsedClean.pathname;
            if (basePath && basePath !== "/" && path.startsWith(basePath)) {
              finalUrl = `${parsedClean.origin}${path}`;
            }
          } catch (e) {
            // ignore
          }

          // Defensive design: Provide fields based on observed UI
          addResponse = await fetch(finalUrl, {
            method: "POST",
            headers: requestHeaders,
            body: JSON.stringify({
              remark: host.remark,
              address: host.endpoint,
              domain: host.endpoint, // Support both address and domain for structural mapping
              inbound: host.inbound || "",
              inboundTag: host.inbound || "", // Support both inbound and inboundTag fields
              inboundId: inboundId, // Core required field for /panel/api/hosts/add
              inbound_id: inboundId, // Alternative naming for some database schemas
              port: Number(host.port) || 443,
              enable: host.enable !== false,
              security: host.security || "same"
            }),
            signal: addController.signal
          });
        } catch (fetchErr: any) {
          lastError = fetchErr.name === "AbortError" || fetchErr.message?.includes("aborted") 
            ? "Request timed out (8s)" 
            : (fetchErr.message || "Network error");
          
          pathDiagnostics.push({
            path,
            error: lastError
          });
          
          clearTimeout(addTimeout);
          continue;
        }

        clearTimeout(addTimeout);

        try {
          const respText = await addResponse.text();
          const isHtml = respText.trim().startsWith("<") || respText.toLowerCase().includes("<html");
          
          let respJson: any = null;
          let parseSuccess = false;
          if (!isHtml) {
            try {
              respJson = JSON.parse(respText);
              parseSuccess = true;
            } catch (e) {
              // ignore
            }
          }

          pathDiagnostics.push({
            path,
            status: addResponse.status,
            isHtml,
            parseSuccess,
            snippet: respText.slice(0, 300).trim()
          });

          if (addResponse.status === 200) {
            if (isHtml) {
              lastError = "Response is an HTML page (likely redirect to login or wrong custom path).";
            } else if (parseSuccess && respJson && respJson.success === false) {
              lastError = respJson.msg || "Operation failed in panel";
            } else if (!parseSuccess) {
              lastError = "Response is not valid JSON. Expected a JSON success indicator.";
            } else {
              hostSynced = true;
              workingPath = path; // Save the working path
              break;
            }
          } else if (addResponse.status === 404) {
            lastError = "404 Not Found";
          } else {
            lastError = respJson?.msg || `HTTP ${addResponse.status}: ${respText.slice(0, 100)}`;
          }
        } catch (err: any) {
          lastError = err.message || "Parse error";
          pathDiagnostics.push({
            path,
            error: lastError
          });
        }
      }

      if (hostSynced) {
        successCount++;
        results.push({ 
          ip: host.endpoint, 
          success: true,
          workingPath,
          diagnostics: pathDiagnostics
        });
      } else {
        failCount++;
        results.push({ 
          ip: host.endpoint, 
          success: false, 
          error: lastError,
          diagnostics: pathDiagnostics 
        });
      }
    }

    const firstFailResult = results.find(r => !r.success);
    const mostRepresentativeError = firstFailResult ? firstFailResult.error : "Unknown error";

    res.json({
      success: successCount > 0,
      total: hosts.length,
      successCount,
      failCount,
      error: successCount === 0 ? mostRepresentativeError : undefined,
      results
    });

  } catch (err: any) {
    console.error("3x-ui sync error:", err);
    res.status(500).json({ error: err.message || "Internal server error during sync" });
  }
});

// Start Server & Integrate Vite Middleware
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Cloudflare Scanner Server running on http://localhost:${PORT}`);
  });
}

startServer();
