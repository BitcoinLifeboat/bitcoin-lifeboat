import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const docsSiteDir = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const outPath = path.join(docsSiteDir, 'src/assets/recovery-readiness-map.png');
const width = 1200;
const height = 720;
const data = Buffer.alloc((width * 4 + 1) * height);

for (let y = 0; y < height; y += 1) {
  const rowStart = y * (width * 4 + 1);
  data[rowStart] = 0;
  for (let x = 0; x < width; x += 1) {
    const offset = rowStart + 1 + x * 4;
    const u = x / width;
    const v = y / height;
    const glow = Math.max(0, 1 - Math.hypot(u - 0.68, v - 0.42) * 1.8);
    data[offset] = Math.round(18 + 32 * u + 82 * glow);
    data[offset + 1] = Math.round(53 + 52 * v + 80 * glow);
    data[offset + 2] = Math.round(70 + 42 * (1 - u) + 34 * glow);
    data[offset + 3] = 255;
  }
}

drawGrid();
drawRoute();
drawCard(92, 90, 320, 140, [248, 250, 252], 238);
drawCard(786, 418, 310, 166, [248, 250, 252], 232);
drawDocument(132, 126);
drawChecklist(838, 468);
drawBeacon(648, 302);

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, png(width, height, data));

function drawGrid() {
  for (let x = 0; x < width; x += 72) {
    line(x, 0, x, height, [255, 255, 255], 20, 1);
  }
  for (let y = 0; y < height; y += 72) {
    line(0, y, width, y, [255, 255, 255], 18, 1);
  }
}

function drawRoute() {
  const points = [
    [214, 180],
    [332, 262],
    [460, 254],
    [584, 326],
    [704, 306],
    [842, 508],
  ];

  for (let i = 1; i < points.length; i += 1) {
    const [x1, y1] = points[i - 1];
    const [x2, y2] = points[i];
    line(x1, y1, x2, y2, [245, 158, 11], 235, 8);
    line(x1, y1, x2, y2, [15, 23, 42], 90, 3);
  }

  for (const [x, y] of points) {
    circle(x, y, 18, [20, 184, 166], 255);
    circle(x, y, 9, [240, 253, 250], 255);
  }
}

function drawDocument(x, y) {
  rect(x, y, 182, 104, [15, 23, 42], 70);
  rect(x + 12, y + 12, 158, 12, [20, 184, 166], 220);
  rect(x + 12, y + 40, 118, 10, [51, 65, 85], 150);
  rect(x + 12, y + 62, 138, 10, [51, 65, 85], 120);
  rect(x + 12, y + 84, 92, 10, [51, 65, 85], 100);
}

function drawChecklist(x, y) {
  for (let i = 0; i < 4; i += 1) {
    const yPos = y + i * 30;
    rect(x, yPos, 20, 20, [20, 184, 166], 235);
    line(x + 5, yPos + 10, x + 9, yPos + 15, [255, 255, 255], 255, 3);
    line(x + 9, yPos + 15, x + 16, yPos + 5, [255, 255, 255], 255, 3);
    rect(x + 34, yPos + 5, 142 - i * 18, 10, [30, 41, 59], 135);
  }
}

function drawBeacon(x, y) {
  circle(x, y, 74, [20, 184, 166], 42);
  circle(x, y, 48, [20, 184, 166], 74);
  circle(x, y, 22, [245, 158, 11], 240);
  circle(x, y, 10, [255, 251, 235], 255);
}

function drawCard(x, y, w, h, color, alpha) {
  rect(x, y, w, h, color, alpha);
  line(x, y, x + w, y, [255, 255, 255], 110, 2);
  line(x, y + h, x + w, y + h, [15, 23, 42], 80, 2);
}

function rect(x, y, w, h, color, alpha) {
  for (let yy = Math.max(0, y); yy < Math.min(height, y + h); yy += 1) {
    for (let xx = Math.max(0, x); xx < Math.min(width, x + w); xx += 1) {
      blend(xx, yy, color, alpha);
    }
  }
}

function circle(cx, cy, radius, color, alpha) {
  const r2 = radius * radius;
  for (let y = Math.max(0, cy - radius); y < Math.min(height, cy + radius); y += 1) {
    for (let x = Math.max(0, cx - radius); x < Math.min(width, cx + radius); x += 1) {
      if ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= r2) {
        blend(x, y, color, alpha);
      }
    }
  }
}

function line(x1, y1, x2, y2, color, alpha, thickness) {
  const steps = Math.max(Math.abs(x2 - x1), Math.abs(y2 - y1));
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    const x = Math.round(x1 + (x2 - x1) * t);
    const y = Math.round(y1 + (y2 - y1) * t);
    circle(x, y, thickness, color, alpha);
  }
}

function blend(x, y, color, alpha) {
  const offset = y * (width * 4 + 1) + 1 + x * 4;
  const a = alpha / 255;
  data[offset] = Math.round(data[offset] * (1 - a) + color[0] * a);
  data[offset + 1] = Math.round(data[offset + 1] * (1 - a) + color[1] * a);
  data[offset + 2] = Math.round(data[offset + 2] * (1 - a) + color[2] * a);
}

function png(pngWidth, pngHeight, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(pngWidth, 0);
  ihdr.writeUInt32BE(pngHeight, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const compressed = zlib.deflateSync(rgba, { level: 9 });
  return Buffer.concat([signature, chunk('IHDR', ihdr), chunk('IDAT', compressed), chunk('IEND', Buffer.alloc(0))]);
}

function chunk(type, payload) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, payload])), 0);
  return Buffer.concat([length, typeBuffer, payload, crc]);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
