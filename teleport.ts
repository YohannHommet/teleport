#!/usr/bin/env bun
import { createReadStream, createWriteStream } from "fs";
import { createSocket } from "dgram";
import { createServer, connect } from "net";
import { networkInterfaces } from "os";

const [cmd, ...args] = process.argv.slice(2);
const MCAST_ADDR = "239.255.255.250";
const MCAST_PORT = 5007;

function getIPv4() {
  for (const iface of Object.values(networkInterfaces()))
    for (const info of iface || [])
      if (info.family === "IPv4" && !info.internal) return info.address;
  return "127.0.0.1";
}

if (cmd === "send") {
  const file = args[0];
  if (!file) throw "Usage: teleport send <file>";

  const server = createServer((sock) => createReadStream(file).pipe(sock));
  server.listen(0, () => {
    const port = (server.address() as any).port;
    const sock = createSocket("udp4");
    const beacon = JSON.stringify({ file, port });
    setInterval(() => sock.send(beacon, MCAST_PORT, MCAST_ADDR), 1000);
    console.log(`📡 Broadcasting ${file} on ${getIPv4()}:${port}`);
  });
} else {
  let bytes = 0, last = Date.now();

  const sock = createSocket("udp4");
  sock.bind(MCAST_PORT, () => sock.addMembership(MCAST_ADDR));
  sock.on("message", (buf) => {
    const { file, port } = JSON.parse(buf.toString());
    const out = `./${crypto.randomUUID()}-${file.split("/").pop()}`;
    console.log(`🔍 Found ${file} – downloading as ${out}`);
    connect(port, getIPv4()).pipe(createWriteStream(out));
  });
  sock.on("data", (chunk) => {
    bytes += chunk.length;
    const now = Date.now(), mbps = (bytes / (now - last) * 1000 / 1024 / 1024).toFixed(1);
    process.stdout.write(`\r${(bytes / 1024 / 1024).toFixed(1)} MB @ ${mbps} MB/s`);
  });
  console.log("👂 Listening for peers…");
}