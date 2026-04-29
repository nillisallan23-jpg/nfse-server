import fs from 'fs';
import https from 'https';
import forge from 'node-forge';

/**
 * Converte o Buffer de um PFX para PEM (Chave Privada, Certificado e Cadeia CA)
 * Resolve o erro TS2304 (Cannot find name 'pfxParaPem')
 */
export function pfxParaPem(pfxBuffer: Buffer, password: string) {
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, password);

  let keyPem = '';
  let certPem = '';
  let caPem = '';

  // Extrai chave privada
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (keyBag && keyBag[0]) {
    keyPem = forge.pki.privateKeyToPem(keyBag[0].key!);
  }

  // Extrai certificados
  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBag = certBags[forge.pki.oids.certBag];
  if (certBag) {
    certBag.forEach((bag: any) => {
      const pem = forge.pki.certificateToPem(bag.cert);
      if (bag.attributes && bag.attributes.friendlyName) {
        // Geralmente o certificado do cliente tem atributos, as CAs não
        certPem = pem;
      } else {
        caPem += pem;
      }
    });
    // Fallback: se não identificou pelo friendlyName, pega o primeiro
    if (!certPem && certBag[0]) certPem = forge.pki.certificateToPem(certBag[0].cert);
  }

  return { keyPem, certPem, caPem };
}

/**
 * Cria o agente HTTPS fundindo os certificados do PFX com o bundle ICP-Brasil.
 * O 'export' resolve o erro TS2306 (is not a module)
 */
export function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  
  // Tenta ler da variável Base64 (Railway) ou do arquivo físico
  let pfxBuffer: Buffer;
  try {
    if (process.env.CERT_PFX_BASE64) {
      pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    } else {
      pfxBuffer = fs.readFileSync(pfxPath);
    }
  } catch (err: any) {
    console.error('❌ Erro crítico ao carregar PFX:', err.message);
    throw err;
  }

  // 1. Obtemos o material do PFX
  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

  const caArray: string[] = [];

  // 2. FUSÃO: Bundle externo (ICP-Brasil)
  // Nota: Verifique se essa pasta existe no seu repositório Git
  const bundlePath = './certs/icp-brasil/icp-bundle.pem'; 
  try {
    if (fs.existsSync(bundlePath)) {
      const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
      const bundleCerts = bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g)
        .map(s => s.trim())
        .filter(s => s.length > 0);
      
      caArray.push(...bundleCerts);
      console.log(`🛡️ FUSÃO: ${bundleCerts.length} certificados do governo adicionados.`);
    } else {
      console.warn(`⚠️ Bundle não encontrado em: ${bundlePath}. Usando apenas certificados do PFX.`);
    }
  } catch (err: any) {
    console.error('⚠️ Erro ao fundir bundle externo:', err.message);
  }

  // 3. FUSÃO: Cadeia do próprio PFX
  if (caPem) {
    const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g)
      .map(s => s.trim())
      .filter(s => s.length > 0);
    caArray.push(...fromPfx);
  }

  // 4. Adiciona o certificado cliente na lista de confiança
  if (certPem) caArray.push(certPem.trim());

  console.log(`🔐 AGENTE HTTPS FINAL: ${caArray.length} certificados no total.`);

  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized: true,
  });
}
