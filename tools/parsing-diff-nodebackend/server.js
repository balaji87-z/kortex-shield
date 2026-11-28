// Step-27: reference Node.js backend for the parsing differential.
//
// Node's http module (llhttp) parses the request line, the headers and the
// framing itself and answers 400 on its own for what it refuses. Every
// request it accepts is answered with a JSON description of what it saw, in
// the shape of tools/step23_parsing_backend.py. The body is parsed with the
// standard library only: URLSearchParams for forms, JSON.parse for JSON.
// Node has no standard multipart or XML parser: those are reported as
// kind "not-measured". leftover_len is not measured on this backend (null).
//
// Usage: node server.js PORT   (run in a container; publish the port on 127.0.0.1 only, rule 6)
const http = require('http');
const crypto = require('crypto');

function jsonStrings(doc, out) {
  if (Array.isArray(doc)) doc.forEach((v) => jsonStrings(v, out));
  else if (doc && typeof doc === 'object') {
    for (const [k, v] of Object.entries(doc)) { out.push(k); jsonStrings(v, out); }
  } else if (typeof doc === 'string') out.push(doc);
}

function parseBody(contentType, body) {
  const media = (contentType || '').split(';')[0].trim().toLowerCase();
  const out = { kind: 'none', strings: [], file_strings: [], error: null };
  try {
    if (media === 'application/x-www-form-urlencoded') {
      out.kind = 'urlencoded';
      for (const [k, v] of new URLSearchParams(body.toString('utf8'))) { out.strings.push(k); out.strings.push(v); }
    } else if (media === 'application/json' || media.endsWith('+json')) {
      out.kind = 'json';
      jsonStrings(JSON.parse(body.toString('utf8')), out.strings);
    } else if (media === 'multipart/form-data' || media === 'application/xml' || media === 'text/xml' || media.endsWith('+xml')) {
      out.kind = 'not-measured';
    }
  } catch (e) {
    out.error = e.constructor.name;
  }
  return out;
}

function headerValues(req, name) {
  const out = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === name) out.push(req.rawHeaders[i + 1]);
  }
  return out;
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const target = req.url;
    const cut = target.indexOf('?');
    const pathRaw = cut < 0 ? target : target.slice(0, cut);
    const queryRaw = cut < 0 ? '' : target.slice(cut + 1);
    let pathDecoded;
    try { pathDecoded = decodeURIComponent(pathRaw); } catch (e) { pathDecoded = 'decode-error:' + pathRaw; }
    const query = {};
    for (const [k, v] of new URLSearchParams(queryRaw)) { (query[k] = query[k] || []).push(v); }
    const te = headerValues(req, 'transfer-encoding');
    const cl = headerValues(req, 'content-length');
    const view = {
      backend: 'node-http',
      method: req.method,
      target: target,
      path_raw: pathRaw,
      path_decoded: pathDecoded,
      query_raw: queryRaw,
      query_decoded: Object.fromEntries(Object.keys(query).sort().map((k) => [k, query[k]])),
      content_length_headers: cl,
      transfer_encoding_headers: te,
      body_framing: te.length ? 'transfer-encoding:' + te.join(',') : (cl.length ? 'content-length' : 'none'),
      body_len: body.length,
      body_sha256: crypto.createHash('sha256').update(body).digest('hex'),
      leftover_len: null,
      body_parse: parseBody(req.headers['content-type'], body),
    };
    const payload = Buffer.from(JSON.stringify(view));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': payload.length, Connection: 'close' });
    res.end(payload);
  });
});
server.listen(parseInt(process.argv[2], 10), '0.0.0.0');
