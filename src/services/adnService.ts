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

function pfxParaPem(pfxBuffer: Buffer, senha: string): PemMaterial {
  const senhaLen = senha?.length ?? 0;
  console.log(`🔑 AUDITORIA SENHA: Presente? ${senhaLen > 0 ? 'Sim' : 'NÃO'} | Caracteres: ${senhaLen}`);

  const pfxBinary = pfxBuffer.toString('binary');
  let p12Asn1: forge.asn1.Asn1;

  try {
    p12Asn1 = forge.asn1.fromDer(pfxBinary);
  } catch (errAsn1: any) {
    console.error(`❌ FALHA ASN.1: arquivo corrompido ou formato inválido.`);
    throw new Error(`PFX inválido: ${errAsn1.message}`);
  }

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
    console.log('✅ PFX aberto com sucesso.');
  } catch (e1: any) {
    console.error(`⚠️ Erro na senha principal: ${e1.message}`);
    try {
      p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, '');
      console.log('✅ PFX aberto com SENHA VAZIA.');
    } catch (e2: any) {
      throw new Error(`Senha incorreta ou arquivo corrompido: ${e1.message}`);
    }
  }

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ||
                  p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];

  if (!keyBags || !keyBags[0]?.key) throw new Error('Chave privada não encontrada.');
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const allCerts = certBags.filter((b) => b.cert).map((b) => b.cert!);

  console.log(`🔗 CADEIA DE CERTIFICADOS: ${allCerts.length} encontrados.`);
  allCerts.forEach((cert, idx) => {
    console.log(`   [${idx}] CN: ${cert.subject.getField('CN')?.value} | Expira: ${cert.validity.notAfter}`);
  });

  const certPem = forge.pki.certificateToPem(allCerts[0]);
  const caPem = allCerts.slice(1).map((c) => forge.pki.certificateToPem(c)).join('\n');

  return { keyPem, certPem, caPem: caPem || undefined };
}

function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  let pfxBuffer: Buffer;

  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    console.log(`🔐 Usando CERT_PFX_BASE64 (${pfxBuffer.length} bytes)`);
  } else {
    console.log(`🔍 AUDITORIA ARQUIVO: Lendo de ${pfxPath}`);
    if (!fs.existsSync(pfxPath)) throw new Error(`Arquivo não encontrado: ${pfxPath}`);
    pfxBuffer = fs.readFileSync(pfxPath);
  }

  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);
  const caArray = caPem ? caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g).map(s => s.trim()) : undefined;

  const ambiente = process.env.ADN_AMBIENTE || 'homologacao';
  const rejectUnauthorized = ambiente === 'producao';
  console.log(`🔐 AGENTE HTTPS: Ambiente=${ambiente} | rejectUnauthorized=${rejectUnauthorized}`);

  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized,
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

    return {
      sucesso: true,
      mensagem: 'Sucesso',
      protocolo: response.data?.protocolo,
      respostaRaw: response.data,
    };
  } catch (error: any) {
    const body = error.response?.data;
    console.error(`❌ Erro HTTP ${error.response?.status}:`, body || error.message);
    return {
      sucesso: false,
      mensagem: body?.mensagem || error.message,
      respostaRaw: body,
    };
  }
};
