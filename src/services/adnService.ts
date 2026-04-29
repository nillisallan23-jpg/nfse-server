import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import zlib from 'zlib';

/**
 * Converte o PFX para PEM com extração robusta (mTLS Fix)
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

  const bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBag = bags[forge.pki.oids.certBag];

  if (certBag) {
    const clientCert = certBag.find((b: any) => b.attributes && b.attributes.localKeyId);
    if (clientCert) {
      certPem = forge.pki.certificateToPem(clientCert.cert);
    } else if (certBag[0]) {
      certPem = forge.pki.certificateToPem(certBag[0].cert);
    }

    certBag.forEach((bag: any) => {
      const pem = forge.pki.certificateToPem(bag.cert);
      if (pem.trim() !== certPem.trim()) {
        caPem += pem + '\n';
      }
    });
  }

  return { keyPem, certPem, caPem };
}

/**
 * Cria o Agente HTTPS com mTLS
 */
export function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  
  let pfxBuffer: Buffer;
  
  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
  } else {
    if (!fs.existsSync(pfxPath)) {
      console.error(`❌ PFX não encontrado.`);
      return new https.Agent();
    }
    pfxBuffer = fs.readFileSync(pfxPath);
  }

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
 * 🚀 FUNÇÃO PRINCIPAL: Emissão Nacional
 */
export const emitirNotaNacional = async (xml: string) => {
  try {
    const agente = criarAgenteMTLS();
    
    // Compressão Gzip -> Base64
    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    
    /**
     * AJUSTE DE URL:
     * O erro ENOTFOUND indica que o domínio api.portalfiscal.inf.br pode estar inacessível
     * Verifique se para o ADN/SERPRO a URL não é: sefin.nfse.gov.br ou similar.
     */
    const url = `https://api.portalfiscal.inf.br/nfs-e/v1/emissao`;

    console.log(`📡 Tentando conexão com: ${url}`);

    const resposta = await axios.post(url, { xml: xmlBase64 }, {
      httpsAgent: agente,
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000 // 15 segundos
    });

    return { sucesso: true, dados: resposta.data };

  } catch (error: any) {
    // Tratamento para erro de DNS/Conexão
    if (error.code === 'ENOTFOUND') {
      return {
        sucesso: false,
        mensagem: "Erro de DNS: Não foi possível encontrar o servidor da API Nacional. Verifique a URL ou a conexão do Railway.",
        detalhes: error.hostname
      };
    }

    return {
      sucesso: false,
      mensagem: error.response?.data?.mensagem || error.message,
      detalhes: error.response?.data
    };
  }
};
