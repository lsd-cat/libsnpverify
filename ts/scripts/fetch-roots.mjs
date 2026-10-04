// Regenerates src/roots.ts from AMD KDS. Review the diff before committing: a changed ARK is a big deal.
import fs from 'node:fs';
const products = ['Milan', 'Genoa', 'Turin'];
const target = new URL('../src/roots.ts', import.meta.url);
let out = fs.readFileSync(target, 'utf8').split('const B64')[0];
out += 'const B64: Partial<Record<Product, { ask: string; ark: string }>> = {\n';
for (const p of products) {
  const pem = await (await fetch(`https://kdsintf.amd.com/vcek/v1/${p}/cert_chain`)).text();
  const [ask, ark] = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----/g)].map(m => m[1].replace(/\s+/g, ''));
  out += `  ${p}: {\n    ask: '${ask}',\n    ark: '${ark}',\n  },\n`;
}
out += `};

export function embeddedRoots(product: Product): ProductRoots | undefined {
  const b = B64[product];
  return b && { ask: fromBase64(b.ask), ark: fromBase64(b.ark) };
}
`;
fs.writeFileSync(target, out);
