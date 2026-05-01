import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import zlib from 'zlib';

/**
 * Converte o PFX para PEM com extração vinculada (mTLS Fix)
 * Resolve o erro 'key values mismatch' garantindo o par correto.
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
 * Cria o Agente HTTPS com mTLS e ignora erro de emissor local.
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
      // Resolve "unable to get local issuer certificate"
      rejectUnauthorized: false, 
    });
  }

  return new https.Agent();
}

/**
 * 🚀 FUNÇÃO PRINCIPAL: Emissão Produção Nacional (Ajustada para erro 210)
 */
export const emitirNotaNacional = async (xml: string) => {
  try {
    const agente = criarAgenteMTLS();
    
    // 1. Verificação de segurança: garantir que o XML não chegou vazio
    if (!xml || xml.length < 10) {
      throw new Error("O XML fornecido é inválido ou está vazio.");
    }

    // 2. Compressão Gzip -> Base64
    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    
    const identificador = process.env.IDENTIFICADOR_ENVIO || "ID_PROD";
    const cnpjConcessionaria = process.env.ADN_CNPJ_CONCESSIONARIA || "";
    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';

    console.log(`📡 Enviando para: ${url}`);

    // 3. Payload ajustado: Usando 'Conteudo' e 'XmlGzipBase64' para garantir compatibilidade
    // O erro 210 acontece porque o governo não "viu" o conteúdo no campo anterior.
    const payload = {
      Identificador: identificador,
      CnpjConcessionaria: cnpjConcessionaria,
      Conteudo: xmlBase64, // Campo principal esperado pelo SERPRO para o binário
      XmlGzipBase64: xmlBase64 // Campo de backup
    };

    const resposta = await axios.post(url, payload, {
      httpsAgent: agente,
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 30000 
    });

    console.log("✅ Resposta do Governo recebida!");
    return { sucesso: true, dados: resposta.data };

  } catch (error: any) {
    const erroGoverno = error.response?.data;
    console.error('❌ Erro na Emissão:', JSON.stringify(erroGoverno || error.message));

    return {
      sucesso: false,
      mensagem: "Erro de processamento na API Nacional.",
      detalhes: erroGoverno
    };
  }
};

/**
 * 🔍 FUNÇÃO DE CONSULTA: Para conferir o protocolo guardado
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
