import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import zlib from 'zlib';

/**
 * 🔐 Converte o PFX para PEM com extração de chaves e certificados (mTLS)
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
 * 🛠️ Cria o Agente HTTPS com mTLS e Cadeia ICP-Brasil
 */
export function criarAgenteMTLS(): https.Agent {
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  let pfxBuffer: Buffer = Buffer.alloc(0);

  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
  } else if (process.env.CERT_PFX_PATH && fs.existsSync(process.env.CERT_PFX_PATH)) {
    pfxBuffer = fs.readFileSync(process.env.CERT_PFX_PATH);
  }

  if (pfxBuffer.length > 0) {
    const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);
    const caArray: string[] = [];

    // Tenta carregar o bundle de CAs da ICP-Brasil se existir
    const bundlePath = './certs/icp-brasil/icp-bundle.pem';
    if (fs.existsSync(bundlePath)) {
      const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
      caArray.push(...bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g).filter(s => s.trim()));
    }

    if (caPem) caArray.push(...caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g).filter(s => s.trim()));
    if (certPem) caArray.push(certPem.trim());

    return new https.Agent({
      key: keyPem,
      cert: certPem,
      ca: caArray,
      rejectUnauthorized: false, 
    });
  }

  return new https.Agent();
}

/**
 * 🚀 FUNÇÃO: Envio de XML pronto (Assinado externamente)
 */
export const emitirNotaNacional = async (xml: string) => {
  try {
    const agente = criarAgenteMTLS();
    
    if (!xml || xml.length < 10) throw new Error("XML inválido.");

    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    
    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';

    console.log(`📤 [ADN] Enviando XML Gzip-Base64 (${xmlBase64.length} chars)`);

    const payload = {
      Identificador: process.env.IDENTIFICADOR_ENVIO || "ID_PROD",
      CnpjConcessionaria: process.env.ADN_CNPJ_CONCESSIONARIA || "",
      Conteudo: xmlBase64,       // Campo padrão NFSe-V
      XmlGzipBase64: xmlBase64   // Redundância para ADN
    };

    const resposta = await axios.post(url, payload, {
      httpsAgent: agente,
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000 
    });

    return { sucesso: true, dados: resposta.data };

  } catch (error: any) {
    return { sucesso: false, mensagem: "Erro na comunicação", detalhes: error.response?.data || error.message };
  }
};

/**
 * ✍️ FUNÇÃO: Recebe Dados (JSON), Monta XML, Assina e Envia
 * Use esta função para enviar dados direto do MeConferi/Supabase
 */
export const emitirNotaNacionalFromDados = async (dados: any) => {
  try {
    console.log("🖊️ [ADN] Iniciando montagem e assinatura do XML...");
    
    // Aqui viria a lógica de montagem do XML baseada no seu template DPS
    // Por enquanto, simulamos o fluxo de processamento
    const xmlMontado = `<?xml version="1.0" encoding="UTF-8"?><DPS>...</DPS>`; // Implementar sua montagem aqui

    // Reaproveita a função de envio
    return await emitirNotaNacional(xmlMontado);

  } catch (error: any) {
    return { sucesso: false, mensagem: "Erro na assinatura/montagem", erro: error.message };
  }
};

/**
 * 🔍 FUNÇÃO: Consulta por Protocolo
 */
export const consultarProtocolo = async (protocolo: string) => {
  try {
    const agente = criarAgenteMTLS();
    const url = `https://certificado.api.via.nfse.gov.br/recepcao/consultar/nfsev/${protocolo}`;

    const resposta = await axios.get(url, {
      httpsAgent: agente,
      headers: { 'Accept': 'application/json' },
      timeout: 15000 
    });

    return { sucesso: true, dados: resposta.data };
  } catch (error: any) {
    return { sucesso: false, detalhes: error.response?.data || error.message };
  }
};
