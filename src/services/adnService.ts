import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import zlib from 'zlib';

/**
 * Converte o PFX para PEM
 */
export function pfxParaPem(pfxBuffer: Buffer, password: string) {
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, password);

  let keyPem = '';
  let certPem = '';
  let caPem = '';

  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (keyBag && keyBag[0]) {
    keyPem = forge.pki.privateKeyToPem(keyBag[0].key!);
  }

  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBag = certBags[forge.pki.oids.certBag];
  if (certBag) {
    certBag.forEach((bag: any) => {
      const pem = forge.pki.certificateToPem(bag.cert);
      if (bag.attributes && bag.attributes.friendlyName) {
        certPem = pem;
      } else {
        caPem += pem;
      }
    });
    if (!certPem && certBag[0]) certPem = forge.pki.certificateToPem(certBag[0].cert);
  }

  return { keyPem, certPem, caPem };
}

/**
 * Cria o Agente HTTPS com mTLS e Bundle ICP-Brasil
 */
export function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  
  let pfxBuffer: Buffer;
  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
  } else {
    // Se não encontrar o arquivo, cria um buffer vazio para não quebrar o build, 
    // mas loga o erro para você ver no Railway
    if (!fs.existsSync(pfxPath)) {
        console.error(`❌ Arquivo PFX não encontrado em: ${pfxPath}`);
        pfxBuffer = Buffer.alloc(0);
    } else {
        pfxBuffer = fs.readFileSync(pfxPath);
    }
  }

  // Só tenta converter se houver buffer
  if (pfxBuffer.length > 0) {
      const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);
      const caArray: string[] = [];
      const bundlePath = './certs/icp-brasil/icp-bundle.pem'; 

      if (fs.existsSync(bundlePath)) {
        const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
        const bundleCerts = bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g)
          .map(s => s.trim()).filter(s => s.length > 0);
        caArray.push(...bundleCerts);
      }

      if (caPem) {
        const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g)
          .map(s => s.trim()).filter(s => s.length > 0);
        caArray.push(...fromPfx);
      }
      if (certPem) caArray.push(certPem.trim());

      return new https.Agent({
        key: keyPem,
        cert: certPem,
        ca: caArray,
        rejectUnauthorized: true,
      });
  }

  return new https.Agent();
}

/**
 * 🚀 FUNÇÃO PRINCIPAL EXPORTADA
 */
export const emitirNotaNacional = async (xml: string) => {
  try {
    const agente = criarAgenteMTLS();
    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    const url = `https://api.portalfiscal.inf.br/nfs-e/v1/emissao`; 

    const resposta = await axios.post(url, { xml: xmlBase64 }, {
        httpsAgent: agente,
        headers: { 'Content-Type': 'application/json' }
    });

    return { sucesso: true, dados: resposta.data };
  } catch (error: any) {
    return {
      sucesso: false,
      mensagem: error.response?.data?.mensagem || error.message
    };
  }
};
