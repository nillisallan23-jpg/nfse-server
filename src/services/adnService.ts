import axios from 'axios';
import * as https from 'https';
import * as fs from 'fs';
import * as zlib from 'zlib';
import { promisify } from 'util';
import * as forge from 'node-forge';

const gzip = promisify(zlib.gzip);

export interface AdnEmissionResponse {
  sucesso: boolean;
  mensagem: string;
  protocolo?: string;
  chaveAcesso?: string;
  erros?: any[];
  respostaRaw?: any;
}

interface PemMaterial {
  keyPem: string;
  certPem: string;
  caPem?: string;
}

/**
 * Converte um PFX (.pfx/.p12) em PEM (chave + certificado + CA chain)
 * usando varredura PROFUNDA em todos os safeBags para capturar a cadeia ICP-Brasil.
 */
function pfxParaPem(pfxBuffer: Buffer, senha: string): PemMaterial {
  const pfxBinary = pfxBuffer.toString('binary');
  const p12Asn1 = forge.asn1.fromDer(pfxBinary);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

  const allCerts: forge.pki.Certificate[] = [];
  let privateKey: forge.pki.PrivateKey | null = null;

  // ── Varredura MANUAL para não perder certificados da cadeia ──
  for (const safeContents of p12.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      // Extração da Chave Privada
      if ((safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) && safeBag.key) {
        privateKey = safeBag.key;
      }
      // Extração de TODOS os certificados (Cadeia completa)
      if (safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
        allCerts.push(safeBag.cert);
      }
    }
  }

  if (!privateKey) throw new Error('Chave privada não encontrada no PFX.');
  if (allCerts.length === 0) throw new Error('Nenhum certificado encontrado no PFX.');

  const keyPem = forge.pki.privateKeyToPem(privateKey);
  
  // Identifica o certificado do cliente (o que não é auto-assinado)
  let endEntityIdx = 0;
  for (let i = 0; i < allCerts.length; i++) {
    const c = allCerts[i];
    if (c.subject.getField('CN')?.value !== c.issuer.getField('CN')?.value) {
      endEntityIdx = i;
      break;
    }
  }

  const certPem = forge.pki.certificateToPem(allCerts[endEntityIdx]);
  const chainCerts = allCerts.filter((_, idx) => idx !== endEntityIdx);
  const caPem = chainCerts.map((c) => forge.pki.certificateToPem(c)).join('\n');

  console.log(`🌿 AUDITORIA CADEIA: ${allCerts.length} certificados encontrados no PFX.`);
  return { keyPem, certPem, caPem: caPem || undefined };
}

/**
 * Cria o agente HTTPS injetando a cadeia completa na propriedade 'ca'.
 */
function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  const pfxBuffer = process.env.CERT_PFX_BASE64 
    ? Buffer.from(process.env.CERT_PFX_BASE64, 'base64') 
    : fs.readFileSync(pfxPath);

  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

  // Montagem do caArray para o Node.js
  const caArray: string[] = [];
  if (caPem) {
    const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g).map(s => s.trim()).filter(s => s.length > 0);
    caArray.push(...fromPfx);
  }
  // Inclui o próprio certificado como âncora de confiança se necessário
  if (certPem) caArray.push(certPem.trim());

  console.log(`🔐 AGENTE HTTPS: ${caArray.length} certificados injetados na CA.`);

  const ambiente = process.env.ADN_AMBIENTE || 'homologacao';
  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized: ambiente === 'producao', // Em homologação relaxa a validação
  });
}

export const emitirNotaNacional = async (xmlString: string): Promise<AdnEmissionResponse> => {
  try {
    const bufferXml = Buffer.from(xmlString, 'utf-8');
    const gzippedBuffer = await gzip(bufferXml);
    const xmlBase64Gzip = gzippedBuffer.toString('base64');
    
    const cnpj = (process.env.ADN_CNPJ_CONCESSIONARIA || process.env.PRESTADOR_CNPJ || '').replace(/\D/g, '');
    const payload = {
      cnpjConcessionaria: cnpj,
      identificador: `ENVIO_${Date.now()}`,
      notaFiscalViaXmlGZipBase64: xmlBase64Gzip,
    };

    const httpsAgent = criarAgenteMTLS();
    const url = process.env.ADN_URL_EMISSAO || 'https://sefin.nfse.gov.br/sefinnacional/nfse';

    const response = await axios.post(url, payload, {
      httpsAgent,
      headers: { 'Content-Type': 'application/json' },
      timeout: 60000,
    });

    return { sucesso: true, mensagem: 'Sucesso', protocolo: response.data?.protocolo, respostaRaw: response.data };
  } catch (error: any) {
    const body = error.response?.data;
    console.error(`❌ Erro ADN:`, body || error.message);
    return { sucesso: false, mensagem: body?.mensagem || error.message, respostaRaw: body };
  }
};
