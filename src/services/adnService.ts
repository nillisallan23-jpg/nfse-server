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
    // 🔍 DEBUG: Verificando o conteúdo do XML antes de enviar
    console.log("--------------------------------------------------");
    console.log("📄 [DEBUG] CONTEÚDO DO XML BRUTO QUE SERÁ ENVIADO:");
    console.log(xml);
    console.log("--------------------------------------------------");

    const agente = criarAgenteMTLS();
    
    if (!xml || xml.length < 10) throw new Error("XML fornecido está vazio ou é inválido.");

    const bufferGzip = zlib.gzipSync(xml);
    const xmlBase64 = bufferGzip.toString('base64');
    
    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';

    console.log(`📤 [ADN] Enviando para: ${url}`);
    console.log(`📦 Tamanho do Base64: ${xmlBase64.length} caracteres`);

    const payload = {
      Identificador: process.env.IDENTIFICADOR_ENVIO || "ID_PROD",
      CnpjConcessionaria: process.env.ADN_CNPJ_CONCESSIONARIA || "",
      Conteudo: xmlBase64,
      XmlGzipBase64: xmlBase64,
      xmlGzipBase64: xmlBase64
    };

    const resposta = await axios.post(url, payload, {
      httpsAgent: agente,
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 30000 
    });

    return { sucesso: true, dados: resposta.data };

  } catch (error: any) {
    const erroGoverno = error.response?.data;
    console.error('❌ [ADN] Erro na Emissão:', JSON.stringify(erroGoverno || error.message));

    return {
      sucesso: false,
      mensagem: "Falha na comunicação com a API Nacional.",
      detalhes: erroGoverno
    };
  }
};

/**
 * ✍️ FUNÇÃO: Recebe Dados (JSON), identifica o formato e processa
 */
export const emitirNotaNacionalFromDados = async (dados: any) => {
  try {
    console.log("🖊️ [ADN] Iniciando fluxo de processamento...");
    
    // 🔍 DEBUG: Verificando o JSON completo que chegou
    console.log("📦 [DEBUG] DADOS RECEBIDOS NO SERVICE:", JSON.stringify(dados, null, 2));
    
    // 💡 FLEXIBILIDADE TOTAL: Tenta encontrar o conteúdo em várias chaves possíveis
    const conteudo = dados.xml || dados.dadosDPS || dados;

    if (!conteudo) {
        throw new Error("Nenhum conteúdo válido encontrado para emissão.");
    }

    // CASO 1: O conteúdo já é uma string (XML Assinado vindo do Lovable/Supabase)
    if (typeof conteudo === 'string') {
        console.log("📄 Conteúdo identificado como XML String. Enviando...");
        return await emitirNotaNacional(conteudo);
    }

    // CASO 2: O conteúdo é um objeto (Dados brutos para montagem de XML)
    if (typeof conteudo === 'object') {
        console.log("⚙️ Conteúdo identificado como Objeto. Verificando conversão...");
        
        // Se dentro do objeto existir uma propriedade .xml (caso o objeto esteja aninhado)
        if (conteudo.xml && typeof conteudo.xml === 'string') {
            return await emitirNotaNacional(conteudo.xml);
        }

        // Se chegamos aqui com um objeto e sem XML pronto, o servidor precisaria 
        // de uma função gerarXml(conteudo). Como o Lovable já costuma mandar o XML,
        // vamos garantir que ele tente ler a string se ela existir.
        throw new Error("O servidor recebeu um objeto, mas esperava uma string XML. Verifique o envio do Lovable.");
    }
    
    throw new Error("Formato de dados desconhecido.");

  } catch (error: any) {
    console.error('❌ [ADN] Erro no processamento de dados:', error.message);
    return { 
      sucesso: false, 
      mensagem: "Erro ao processar dados para emissão", 
      erro: error.message 
    };
  }
};

/**
 * 🔍 FUNÇÃO DE CONSULTA: Para conferir o status pelo protocolo
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
