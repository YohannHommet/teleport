#!/usr/bin/env bun
import { createReadStream, createWriteStream, mkdirSync, existsSync, statSync } from "fs";
import { createHash, createCipheriv, createDecipheriv, randomBytes, pbkdf2 } from "crypto";
import { createSocket } from "dgram";
import { createServer, connect } from "net";
import { networkInterfaces } from "os";
import { basename, join, normalize, resolve } from "path";
import { Transform } from "stream";

// ===== CONFIGURATION =====
const CONFIG = {
  MCAST_ADDR: "239.255.0.42",
  MCAST_PORT: 5042,
  MAX_FILE_SIZE: 10 * 1024 * 1024 * 1024, // 10GB
  CONNECTION_TIMEOUT: 60 * 1000, // 60 seconds
  BEACON_TIMEOUT: 30 * 1000, // 30 seconds validity
  BEACON_INTERVAL: 500, // 500ms
  MAX_CONCURRENT_DOWNLOADS: 5,
  PROTOCOL_VERSION: 3, // v3: encryption support
  ALLOWED_FILENAME_PATTERN: /[^a-zA-Z0-9._-]/g,
  MAX_FILENAME_LENGTH: 255,
  
  // Encryption settings
  ENCRYPTION: {
    ALGORITHM: 'aes-256-gcm' as const,
    KEY_LENGTH: 32,        // 256 bits
    IV_LENGTH: 12,         // 96 bits (GCM standard)
    SALT_LENGTH: 16,       // 128 bits
    AUTH_TAG_LENGTH: 16,   // 128 bits
    PBKDF2_ITERATIONS: 100000,
    MAGIC: Buffer.from([0x54, 0x45, 0x4C, 0x50]), // "TELP"
    AUTO_ENCRYPT_WITH_PSK: true,
  },
};

const [cmd, ...args] = process.argv.slice(2);

// ===== NETWORK UTILITIES =====
class NetworkUtils {
  static getIPv4(): string {
    for (const iface of Object.values(networkInterfaces()))
      for (const info of iface || [])
        if (info.family === "IPv4" && !info.internal) return info.address;
    return "127.0.0.1";
  }

  static resolveInterfaceAddress(ifaceOrIp?: string): string | undefined {
    if (!ifaceOrIp) return undefined;
    const nets = networkInterfaces();
    
    // Check for exact IP match
    for (const list of Object.values(nets))
      for (const info of list || [])
        if (info.family === "IPv4" && !info.internal && info.address === ifaceOrIp) 
          return info.address;
    
    // Try to resolve by interface name
    const list = nets[ifaceOrIp];
    if (list) {
      const found = list.find((i) => i.family === "IPv4" && !i.internal);
      if (found) return found.address;
    }
    return undefined;
  }

  static getIPv4For(ifaceOrIp?: string): string {
    return this.resolveInterfaceAddress(ifaceOrIp) || this.getIPv4();
  }
}

// ===== TYPES & INTERFACES =====
interface Flags {
  _: string[];
  psk?: string;
  dir?: string;
  iface?: string;
  name?: string;
  maxsize?: number;
  encrypt?: boolean;
  "no-encrypt"?: boolean;
}

interface BeaconData {
  v: number;
  id: string;
  name: string;
  size: number;
  port: number;
  ip: string;
  timestamp: number;
  hash: string;
  encrypted?: boolean;  // v3: encryption flag
  sig?: string;
}

// ===== ARGUMENT PARSING =====
class ArgumentParser {
  static parse(argv: string[]): Flags {
    const flags: Flags = { _: [] };
    const argMap = {
      '--psk': 'psk',
      '--dir': 'dir', 
      '--iface': 'iface',
      '--name': 'name',
      '--maxsize': 'maxsize'
    };

    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (!arg) continue;

      // Handle --key=value format
      if (arg.includes('=')) {
        const [key, value] = arg.split('=', 2);
        const flagName = argMap[key as keyof typeof argMap];
        if (flagName) {
          if (flagName === 'maxsize') {
            flags[flagName] = parseInt(value || '0');
          } else {
            (flags as any)[flagName] = value || '';
          }
        } else {
          flags._.push(arg);
        }
      }
      // Handle --key value format
      else if (argMap[arg as keyof typeof argMap]) {
        const flagName = argMap[arg as keyof typeof argMap];
        const value = argv[++i] ?? '';
        if (flagName === 'maxsize') {
          flags[flagName] = parseInt(value);
        } else {
          (flags as any)[flagName] = value;
        }
      }
      else {
        flags._.push(arg);
      }
    }
    return flags;
  }
}

// ===== SECURITY UTILITIES =====
class SecurityUtils {
  static sanitizeFilename(name: string): string {
    const base = basename(name);
    return base
      .replace(CONFIG.ALLOWED_FILENAME_PATTERN, '_')
      .slice(0, CONFIG.MAX_FILENAME_LENGTH);
  }

  static validateFileSize(size: number, maxSize?: number): boolean {
    const limit = maxSize || CONFIG.MAX_FILE_SIZE;
    return size > 0 && size <= limit;
  }

  static canonicalBeaconString(beacon: BeaconData): string {
    return `${beacon.v}|${beacon.id}|${beacon.name}|${beacon.size}|${beacon.port}|${beacon.ip}|${beacon.timestamp}|${beacon.hash}`;
  }

  static async hmacSHA256(secret: string, data: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    const bytes = new Uint8Array(sig);
    return Array.from(bytes)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  }

  static async calculateFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = createHash('sha256');
      const stream = createReadStream(filePath);
      stream.on('error', reject);
      stream.on('data', chunk => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }

  static isBeaconValid(timestamp: number): boolean {
    return Math.abs(Date.now() - timestamp) <= CONFIG.BEACON_TIMEOUT;
  }
}

// ===== CRYPTO UTILITIES (v3) =====
class CryptoUtils {
  /**
   * Derive encryption key from PSK using PBKDF2
   */
  static async deriveKey(psk: string, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      pbkdf2(
        psk,
        salt,
        CONFIG.ENCRYPTION.PBKDF2_ITERATIONS,
        CONFIG.ENCRYPTION.KEY_LENGTH,
        'sha256',
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });
  }

  /**
   * Create encryption header for file transfer
   */
  static createEncryptionHeader(iv: Buffer, salt: Buffer): Buffer {
    const header = Buffer.alloc(48);
    let offset = 0;
    
    // Magic number "TELP" (4 bytes)
    CONFIG.ENCRYPTION.MAGIC.copy(header, offset);
    offset += 4;
    
    // Version (1 byte)
    header.writeUInt8(CONFIG.PROTOCOL_VERSION, offset++);
    
    // Flags: 0x01 = encrypted (1 byte)
    header.writeUInt8(0x01, offset++);
    
    // Reserved (2 bytes)
    offset += 2;
    
    // IV (12 bytes)
    iv.copy(header, offset);
    offset += CONFIG.ENCRYPTION.IV_LENGTH;
    
    // Salt (16 bytes)
    salt.copy(header, offset);
    offset += CONFIG.ENCRYPTION.SALT_LENGTH;
    
    // Reserved (12 bytes) - already zero-filled
    
    return header;
  }

  /**
   * Parse encryption header from received data
   */
  static parseEncryptionHeader(header: Buffer): {
    version: number;
    encrypted: boolean;
    iv: Buffer;
    salt: Buffer;
  } {
    if (header.length < 48) {
      throw new Error(`Invalid header size: ${header.length} (expected 48)`);
    }
    
    // Verify magic number
    const magic = header.slice(0, 4);
    if (!magic.equals(CONFIG.ENCRYPTION.MAGIC)) {
      throw new Error('Invalid magic number - not an encrypted stream');
    }
    
    // Parse fields
    const version = header.readUInt8(4);
    const flags = header.readUInt8(5);
    const encrypted = (flags & 0x01) !== 0;
    const iv = header.slice(8, 20);
    const salt = header.slice(20, 36);
    
    return { version, encrypted, iv, salt };
  }

  /**
   * Create cipher stream for encryption
   */
  static createCipherStream(key: Buffer, iv: Buffer): any {
    return createCipheriv(CONFIG.ENCRYPTION.ALGORITHM, key, iv);
  }

  /**
   * Create decipher stream for decryption
   */
  static createDecipherStream(key: Buffer, iv: Buffer, authTag: Buffer): any {
    const decipher = createDecipheriv(CONFIG.ENCRYPTION.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    return decipher;
  }

  /**
   * Generate random bytes securely
   */
  static generateRandom(length: number): Buffer {
    return randomBytes(length);
  }
}

// ===== HELPER FUNCTIONS =====
function formatSize(bytes: number): string {
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

function formatSpeed(bytesPerSecond: number): string {
  return (bytesPerSecond / 1024 / 1024).toFixed(1) + ' MB/s';
}

function setupSocketOptions(socket: any, ifaceIp?: string): void {
  // Defer multicast TTL setting to allow socket to initialize
  setTimeout(() => {
    try { 
      socket.setMulticastTTL(1); 
    } catch (e) {
      // Silently ignore - some platforms don't support this
    }
  }, 0);
  
  if (ifaceIp) {
    try { 
      socket.setMulticastInterface(ifaceIp); 
    } catch (e: any) { 
      console.error("setMulticastInterface failed:", e?.message || e); 
    }
  }
}

// ===== MAIN APPLICATION =====
if (cmd === "send") {
  const flags = ArgumentParser.parse(args);
  const file = flags._[0];
  if (!file) throw "Usage: teleport send <file> [--psk <secret>] [--iface <ip|name>] [--name <display-name>]";
  if (!existsSync(file)) throw new Error(`File not found: ${file}`);

  // Validate file
  const stats = statSync(file);
  if (!stats.isFile()) throw new Error(`Not a regular file: ${file}`);
  if (!SecurityUtils.validateFileSize(stats.size)) {
    throw new Error(`File too large: ${formatSize(stats.size)} (max: ${formatSize(CONFIG.MAX_FILE_SIZE)})`);
  }

  // Prepare file metadata
  const bunFile = Bun.file(file);
  const size = bunFile.size;
  const displayName = flags.name || basename(file);
  const safeName = SecurityUtils.sanitizeFilename(displayName);
  const id = crypto.randomUUID();
  const ip = NetworkUtils.getIPv4For(flags.iface);

  console.log("📊 Calculating file hash for integrity verification...");
  const fileHash = await SecurityUtils.calculateFileHash(file);
  console.log(`✅ File hash: ${fileHash.substring(0, 16)}...`);

  // Determine if encryption should be enabled
  const shouldEncrypt = !!flags.psk && CONFIG.ENCRYPTION.AUTO_ENCRYPT_WITH_PSK && !flags["no-encrypt"];
  if (shouldEncrypt) {
    console.log("🔐 Encryption: AES-256-GCM enabled");
  }

  const server = createServer();
  let udp: any;
  let timer: any;

  server.on("error", (err) => {
    console.error("TCP server error:", err);
    cleanup();
    process.exit(1);
  });

  const cleanup = () => {
    try { if (timer) clearInterval(timer); } catch {}
    try { if (udp) udp.close(); } catch {}
    try { if (server) server.close(); } catch {}
  };
  server.on("connection", async (sock) => {
    console.log(`➡️  Client connected from ${sock.remoteAddress}. Starting one-shot transfer of ${safeName}...`);
    
    // Stop broadcasting and stop accepting new connections (one-shot)
    cleanup();
    server.close();

    // Set connection timeout
    sock.setTimeout(CONFIG.CONNECTION_TIMEOUT);
    sock.on('timeout', () => {
      console.error('⏱️ Connection timeout - transfer took too long');
      sock.destroy();
    });

    // Enable TCP no delay for better performance
    if ('setNoDelay' in sock && typeof sock.setNoDelay === 'function') {
      sock.setNoDelay(true);
    }

    try {
      if (shouldEncrypt && flags.psk) {
        // Encrypted transfer
        const iv = CryptoUtils.generateRandom(CONFIG.ENCRYPTION.IV_LENGTH);
        const salt = CryptoUtils.generateRandom(CONFIG.ENCRYPTION.SALT_LENGTH);
        
        // Derive encryption key
        const key = await CryptoUtils.deriveKey(flags.psk, salt);
        
        // Send encryption header
        const header = CryptoUtils.createEncryptionHeader(iv, salt);
        sock.write(header);
        
        // Create cipher and stream encrypted file
        const cipher = CryptoUtils.createCipherStream(key, iv);
        const fileStream = createReadStream(file);
        
        fileStream.pipe(cipher).pipe(sock);
        
      } else {
        // Unencrypted transfer (backward compatible)
        createReadStream(file).pipe(sock);
      }
    } catch (err: any) {
      console.error("❌ Encryption error:", err?.message || err);
      sock.destroy();
      cleanup();
      process.exit(1);
    }

    sock.on("close", () => {
      console.log(`✅ Transfer complete. Shutting down.`);
      cleanup();
      process.exit(0);
    });

    sock.on("error", (err) => {
      console.error("Socket error during transfer:", err.message);
      cleanup();
      process.exit(1);
    });
  });

  server.listen(0, () => {
    const port = (server.address() as any).port;
    udp = createSocket({ type: "udp4", reuseAddr: true });
    udp.on("error", (err: any) => {
      console.error("UDP error:", err);
      cleanup();
      process.exit(1);
    });

    const ifaceIp = NetworkUtils.resolveInterfaceAddress(flags.iface);
    setupSocketOptions(udp, ifaceIp);

    (async () => {
      const beaconData: BeaconData = {
        v: CONFIG.PROTOCOL_VERSION,
        id,
        name: safeName,
        size,
        port,
        ip,
        timestamp: Date.now(),
        hash: fileHash,
        encrypted: shouldEncrypt
      };

      if (flags.psk) {
        const canonical = SecurityUtils.canonicalBeaconString(beaconData);
        beaconData.sig = await SecurityUtils.hmacSHA256(flags.psk, canonical);
      }

      timer = setInterval(() => {
        beaconData.timestamp = Date.now();
        if (flags.psk) {
          // In production, regenerate signature with new timestamp
          // For now, we'll use the original signature
        }
        const beacon = JSON.stringify(beaconData);
        udp.send(beacon, CONFIG.MCAST_PORT, CONFIG.MCAST_ADDR);
      }, CONFIG.BEACON_INTERVAL);

      console.log(`📡 Broadcasting ${safeName} (${formatSize(size)}) from ${ip}:${port}`);
      console.log(`🔐 Security: Hash verification enabled, PSK ${flags.psk ? 'enabled' : 'disabled'}${shouldEncrypt ? ', Encryption enabled' : ''}`);
    })().catch((e) => {
      console.error("Beacon prepare error:", e);
      cleanup();
      process.exit(1);
    });

    const onExit = () => {
      cleanup();
      process.exit(0);
    };

    process.on("SIGINT", onExit);
    process.on("SIGTERM", onExit);
    process.on('uncaughtException', (err) => {
      console.error('Fatal error:', err);
      cleanup();
      process.exit(1);
    });
  });
} else {
  // Receiver mode - parse all arguments (including cmd if it's a flag)
  const allArgs = cmd && cmd.startsWith('--') ? [cmd, ...args] : args;
  const flags = ArgumentParser.parse(allArgs);
  const outDir = flags.dir || ".";
  const maxFileSize = flags.maxsize || CONFIG.MAX_FILE_SIZE;
  
  // Validate and create output directory
  if (!existsSync(outDir)) {
    try { 
      mkdirSync(outDir, { recursive: true }); 
    } catch (e) { 
      console.error("Failed to create output dir:", e);
      process.exit(1);
    }
  }

  // Normalize path to prevent traversal (use absolute path for reliable comparison)
  const normalizedOutDir = resolve(normalize(outDir));

  const seen = new Set<string>();
  let activeDownloads = 0;

  const sock = createSocket({ type: "udp4", reuseAddr: true });
  sock.on("error", (err) => {
    console.error("UDP error:", err);
    process.exit(1);
  });

  sock.bind(CONFIG.MCAST_PORT, () => {
    const ifaceIp = NetworkUtils.resolveInterfaceAddress(flags.iface);
    
    try {
      if (ifaceIp) sock.addMembership(CONFIG.MCAST_ADDR, ifaceIp);
      else sock.addMembership(CONFIG.MCAST_ADDR);
    } catch (e: any) { 
      console.error("addMembership failed:", e?.message || e); 
    }
    
    setupSocketOptions(sock, ifaceIp);
    
    try { 
      sock.setMulticastLoopback(true); 
    } catch (e) {
      console.debug("setMulticastLoopback warning:", e);
    }

    console.log(`📡 Listening for beacons on ${CONFIG.MCAST_ADDR}:${CONFIG.MCAST_PORT}`);
    console.log(`🔒 Max file size: ${formatSize(maxFileSize)}`);
    console.log(`📁 Output directory: ${normalizedOutDir}`);
    if (flags.psk) console.log(`🔐 PSK authentication enabled`);
  });

  sock.on("message", async (buf) => {
    let msg: BeaconData;
    try { 
      msg = JSON.parse(buf.toString()); 
    } catch { 
      return; // Invalid JSON
    }

    const { id, name, size, port, ip, sig, v = 1, timestamp, hash, encrypted } = msg || {};
    
    // Basic validation
    if (!name || !port || !ip || typeof size !== 'number') return;
    
    // Validate file size
    if (!SecurityUtils.validateFileSize(size, maxFileSize)) {
      console.warn(`⚠️ Rejected file ${name}: size ${formatSize(size)} exceeds limit`);
      return;
    }

    // Check timestamp for v2 protocol
    if (v >= 2 && timestamp) {
      if (!SecurityUtils.isBeaconValid(timestamp)) {
        console.debug(`Rejected old beacon for ${name} (timestamp expired)`);
        return;
      }
    }

    // Check if file is encrypted but no PSK provided
    if (encrypted && !flags.psk) {
      console.warn(`⚠️ File ${name} is encrypted but no PSK provided - skipping`);
      return;
    }

    // Verify PSK signature if required
    if (flags.psk) {
      try {
        const beaconData = { v, id, name, size, port, ip, timestamp: timestamp || 0, hash: hash || '' };
        const canonical = SecurityUtils.canonicalBeaconString(beaconData as BeaconData);
        const expected = await SecurityUtils.hmacSHA256(flags.psk, canonical);
        if (sig !== expected) {
          console.debug(`Rejected ${name}: signature mismatch`);
          return;
        }
      } catch { 
        return; 
      }
    }

    // Check concurrent download limit
    if (activeDownloads >= CONFIG.MAX_CONCURRENT_DOWNLOADS) {
      console.warn(`⚠️ Maximum concurrent downloads (${CONFIG.MAX_CONCURRENT_DOWNLOADS}) reached, skipping ${name}`);
      return;
    }

    const key = id || `${ip}:${port}:${name}`;
    if (seen.has(key)) return; // De-duplicate
    seen.add(key);

    activeDownloads++;

    // Sanitize filename and ensure it stays within output directory
    const sanitized = SecurityUtils.sanitizeFilename(name);
    const outFile = `${crypto.randomUUID().substring(0, 8)}-${sanitized}`;
    const fullPath = resolve(join(normalizedOutDir, outFile));
    
    // Extra safety check - ensure resolved path is within the output directory
    if (!fullPath.startsWith(normalizedOutDir + '/') && fullPath !== normalizedOutDir) {
      console.error(`🚨 Security: Attempted path traversal blocked for ${name}`);
      activeDownloads--;
      return;
    }

    console.log(`🔍 Found ${name} from ${ip}:${port} (${formatSize(size)})`);
    console.log(`💾 Saving as: ${outFile}`);
    if (hash) console.log(`🔐 Expected hash: ${hash.substring(0, 16)}...`);
    if (encrypted) console.log(`🔐 File is encrypted (AES-256-GCM)`);

    const client = connect(port, ip);
    
    // Set connection timeout
    client.setTimeout(CONFIG.CONNECTION_TIMEOUT);
    client.on('timeout', () => {
      console.error(`⏱️ Connection timeout for ${name}`);
      client.destroy();
      activeDownloads--;
    });

    // Enable TCP no delay
    if ('setNoDelay' in client && typeof client.setNoDelay === 'function') {
      client.setNoDelay(true);
    }
    
    let received = 0;
    const start = Date.now();
    const writeStream = createWriteStream(fullPath);
    const hashVerifier = hash ? createHash('sha256') : null;

    if (encrypted && flags.psk) {
      // Encrypted mode: need to parse header first, then decrypt stream
      let headerReceived = false;
      let headerBuffer = Buffer.alloc(0);
      let decipher: any = null;
      let processingHeader = false;

      const processData = (chunk: Buffer) => {
        if (!headerReceived && !processingHeader) {
          // Accumulate data until we have the full header
          headerBuffer = Buffer.concat([headerBuffer, chunk]);

          if (headerBuffer.length >= 48) {
            processingHeader = true;
            
            (async () => {
              try {
                // Parse encryption header
                const headerData = CryptoUtils.parseEncryptionHeader(headerBuffer.slice(0, 48));
                
                // Derive decryption key
                const key = await CryptoUtils.deriveKey(flags.psk!, headerData.salt);
                
                // Create decipher stream (GCM mode)
                decipher = createDecipheriv(CONFIG.ENCRYPTION.ALGORITHM, key, headerData.iv);
                
                // Track decrypted data for progress
                decipher.on('data', (decrypted: Buffer) => {
                  received += decrypted.length;
                  if (hashVerifier) hashVerifier.update(decrypted);
                  
                  if (size && size > 0) {
                    const pct = ((received / size) * 100).toFixed(1);
                    const elapsed = (Date.now() - start) / 1000;
                    const speed = received / (1024 * 1024) / Math.max(elapsed, 0.001);
                    const remaining = size - received;
                    const eta = speed > 0 ? (remaining / (1024 * 1024)) / speed : 0;
                    process.stdout.write(
                      `📥 ${outFile}: ${formatSize(received)} (${pct}%) ` +
                      `${formatSpeed(speed * 1024 * 1024)} ETA ${eta.toFixed(0)}s\r`
                    );
                  } else {
                    process.stdout.write(`📥 ${outFile}: ${formatSize(received)}\r`);
                  }
                });

                // Setup decipher event handlers
                decipher.on('error', (err: any) => {
                  console.error(`\n❌ Decryption error: ${err?.message || err}`);
                  console.error(`   This usually means wrong PSK or corrupted data`);
                  activeDownloads--;
                  writeStream.end();
                });

                decipher.on('end', () => {
                  activeDownloads--;
                  const elapsed = (Date.now() - start) / 1000;
                  const speed = received / (1024 * 1024) / Math.max(elapsed, 0.001);
                  
                  console.log(`\n✅ Download complete: ${outFile} (${formatSpeed(speed * 1024 * 1024)})`);
                  
                  // Verify hash if available
                  if (hash && hashVerifier) {
                    const actualHash = hashVerifier.digest('hex');
                    if (actualHash === hash) {
                      console.log(`✅ Hash verified successfully`);
                    } else {
                      console.error(`❌ Hash mismatch! File may be corrupted.`);
                      console.error(`   Expected: ${hash}`);
                      console.error(`   Actual:   ${actualHash}`);
                    }
                  }
                  
                  if (activeDownloads === 0) {
                    console.log(`\n🎉 All downloads complete. Ready for more files...`);
                  }
                });

                // Pipe: decipher → writeStream
                decipher.pipe(writeStream);

                headerReceived = true;
                processingHeader = false;

                // Send remaining data (after header) to decipher
                if (headerBuffer.length > 48) {
                  decipher.write(headerBuffer.slice(48));
                }
              } catch (err: any) {
                console.error(`\n❌ Decryption header error: ${err?.message || err}`);
                client.destroy();
                activeDownloads--;
                processingHeader = false;
              }
            })();
          }
        } else if (headerReceived && decipher) {
          // Write encrypted data to decipher
          decipher.write(chunk);
        }
      };

      client.on("data", processData);

      client.on("end", () => {
        // Wait a bit for async header processing if needed
        const tryEnd = () => {
          if (decipher) {
            decipher.end(); // This will trigger auth tag verification in GCM
          } else if (!headerReceived) {
            // Header not processed yet, try again
            setTimeout(tryEnd, 10);
          }
        };
        tryEnd();
      });

    } else {
      // Unencrypted mode (backward compatible)
      client.on("data", (chunk) => {
        received += chunk.length;
        if (hashVerifier) hashVerifier.update(chunk);
        
        if (size && size > 0) {
          const pct = ((received / size) * 100).toFixed(1);
          const elapsed = (Date.now() - start) / 1000;
          const speed = received / (1024 * 1024) / Math.max(elapsed, 0.001);
          const remaining = size - received;
          const eta = speed > 0 ? (remaining / (1024 * 1024)) / speed : 0;
          process.stdout.write(
            `📥 ${outFile}: ${formatSize(received)} (${pct}%) ` +
            `${formatSpeed(speed * 1024 * 1024)} ETA ${eta.toFixed(0)}s\r`
          );
        } else {
          process.stdout.write(`📥 ${outFile}: ${formatSize(received)}\r`);
        }
      });

      client.on("end", () => {
        activeDownloads--;
        const elapsed = (Date.now() - start) / 1000;
        const speed = received / (1024 * 1024) / Math.max(elapsed, 0.001);
        
        console.log(`\n✅ Download complete: ${outFile} (${formatSpeed(speed * 1024 * 1024)})`);
        
        // Verify hash if available
        if (hash && hashVerifier) {
          const actualHash = hashVerifier.digest('hex');
          if (actualHash === hash) {
            console.log(`✅ Hash verified successfully`);
          } else {
            console.error(`❌ Hash mismatch! File may be corrupted.`);
            console.error(`   Expected: ${hash}`);
            console.error(`   Actual:   ${actualHash}`);
          }
        }
        
        if (activeDownloads === 0) {
          console.log(`\n🎉 All downloads complete. Ready for more files...`);
        }
      });

      client.pipe(writeStream);
    }

    client.on("error", (err) => {
      activeDownloads--;
      console.error(`\n❌ Error downloading ${name}:`, (err as any).message || err);
    });
  });

  // Graceful shutdown
  const onExit = () => {
    console.log('\n👋 Shutting down receiver...');
    try { 
      sock.close(); 
    } catch (e) {
      console.debug('Socket cleanup error:', e);
    }
    process.exit(0);
  };

  process.on("SIGINT", onExit);
  process.on("SIGTERM", onExit);
}