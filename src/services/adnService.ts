import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import zlib from 'zlib';

/**
 * Converte o PFX para PEM com extração vinculada (mTLS Fix)
 * Esta versão resolve o erro 'key values mismatch' garantindo que o par correto seja extraído.
 */
export function pfxParaPem(pfxBuffer: Buffer, password: string) {
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, password);

  let keyPem = '';
  let certPem = '';
  let caPem = '';

  // 1. Extração da Chave Privada
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (keyBag && keyBag[0]) {
    keyPem = forge.pki.privateKeyToPem(keyBag[0].key!);
  }

  // 2. Extração dos Certificados (Cliente e Cadeia CA)
  const bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBag = bags[forge.pki.oids.certBag];

  if (certBag) {
    // Busca o certificado que possui vínculo com a chave privada (localKeyId)
    const clientCert = certBag.find((b: any) => b.attributes && b.attributes.localKeyId);
    
    if (clientCert) {
      certPem = forge.pki.certificateToPem(clientCert.cert);
    } else if (certBag[0]) {
      certPem = forge.pki.certificateToPem(certBag[0].cert);
    }

    // Organiza os demais como cadeia de confiança
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
 * Cria o Agente HTTPS com mTLS e fusão de bundles (ICP-Brasil + PFX)
 */
export function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  
  let pfxBuffer: Buffer;
  
  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
  } else {
    if (!fs.existsSync(pfxPath)) {
      console.error(`❌ Erro: Arquivo PFX não encontrado em ${pfxPath}`);
      return new https.Agent();
    }
    pfxBuffer = fs.readFileSync(pfxPath);
  }

  if (pfxBuffer.length > 0) {
    const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);
    const caArray: string[] = [];

    // Fusão com o bundle ICP-Brasil do governo
    const bundlePath = './certs/icp-brasil/icp-bundle.pem';
    if (fs.existsSync(bundlePath)) {
      const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
      const bundleCerts = bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g)
        .map(s => s.trim())
        .filter(s => s.length > 0);
      caArray.push(...bundleCerts);
    }

    // Adição da cadeia do próprio PFX
    if (caPem) {
      const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g)
        .map(s => s.trim())
        .filter(s => s.length > 0);
      caArray.push(...fromPfx);
    }

    // Adição do certificado cliente na lista de confiança (Self-Trust)
    if (certPem) caArray.push(certPem.trim());

    return new https.Agent({
      key: keyPem,
      cert: certPem,
      ca: caArray,
      rejectUnauthorized: true, // Segurança máxima ativada
    });
  }

  return new https.Agent();
}

/**
 * 🚀 FUNÇÃO PRINCIPAL: Integração com a API NFS-e Nacional
 * Realiza compressão Gzip e envio via mTLS.
 */
export const emitirNotaNacional = async (xml: string) => {
  try {
    console.log('📡 Iniciando integração com API Nacional...');
    
    const agente = criarAgenteMTLS();
    
    // Preparação do XML conforme padrão SERPRO (Gzip -> Base64)
    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    
    const url = `https://api.portalfiscal.inf.br/nfs-e/v1/emissao`;

    const resposta = await axios.post(url, { xml: xmlBase64 }, {
      httpsAgent: agente,
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 30000 // 30 segundos de timeout
    });

    return { 
      sucesso: true, 
      dados: resposta.data 
    };

  } catch (error: any) {
    const erroDetalhado = error.response?.data || error.message;
    console.error('❌ Erro na API Nacional:', JSON.stringify(erroDetalhado));
    
    return {
      sucesso: false,
      mensagem: erroDetalhado.mensagem || error.message,
      detalhes: erroDetalhado
    };
  }
};
