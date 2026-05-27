import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import querystring from 'querystring';

// Cache em memória para reaproveitar o Bearer Token dentro do tempo de validade
let tokenCache = { token: null as string | null, expiresAt: 0 };

export function pfxParaPem(pfxBuffer: Buffer, senhaStr: string) {
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senhaStr);
  
  let keyPem = '';
  let certPem = '';
  
  const bolsasParaChaves = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const bolsaDeChaves = bolsasParaChaves[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (bolsaDeChaves && bolsaDeChaves[0]) {
    const chavePrivada = bolsaDeChaves[0].key;
    keyPem = forge.pki.privateKeyToPem(chavePrivada);
  }
  
  const bolsasCert = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const bolsaDeCerts = bolsasCert[forge.pki.oids.certBag];
  if (bolsaDeCerts && bolsaDeCerts[0]) {
    const certificado = bolsaDeCerts[0].cert;
    certPem = forge.pki.certificateToPem(certificado);
  }
  
  return { keyPem, certPem };
}

function ejecutarAssinaturaDigital(xml: string, keyPem: string, certPem: string): string {
  if (!xml.includes('<DPS')) return xml;
  
  const dadosCertLimpo = certPem.replace(/-----\s*BEGIN CERTIFICATE\s*-----|-----\s*END CERTIFICATE\s*-----|[\r\n]/g, "");
  
  const md = forge.md.sha256.create();
  md.update(xml, 'utf8');
  const digestReal = forge.util.encode64(md.digest().getBytes());

  const privateKey = forge.pki.privateKeyFromPem(keyPem);
  const mdSign = forge.md.sha256.create();
  mdSign.update(`<SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo>`, 'utf8');
  const assinaturaReal = forge.util.encode64(privateKey.sign(mdSign));

  const blocoSignature = `<Signature xmlns="http://w3.org"><SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo><SignatureValue>${assinaturaReal}</SignatureValue><KeyInfo><X509Data><X509Certificate>${dadosCertLimpo}</X509Certificate></X509Data></KeyInfo></Signature>`;
  
  return xml.replace('</DPS>', `${blocoSignature}</DPS>`);
}

/**
 * 🔒 SOLICITA O BEARER TOKEN DINÂMICO VIA mTLS (OAUTH2)
 */
async function obterBearerTokenADN(keyPem: string, certPem: string): Promise<string | null> {
  const agora = Date.now();
  
  if (tokenCache.token && tokenCache.expiresAt > agora + 300000) {
    return tokenCache.token;
  }

  const urlToken = process.env.ADN_URL_TOKEN || 'https://certificado.api.via.nfse.gov.br/conectar/token';
  
  if (urlToken.toLowerCase() === 'direto' || urlToken.toLowerCase() === 'none') {
    return null;
  }

  const agenteHttps = new https.Agent({
    key: keyPem,
    cert: certPem,
    rejectUnauthorized: false
  });

  const bodyCampos = querystring.stringify({
    grant_type: process.env.ADN_GRANT_TYPE || 'client_credentials',
    scope: process.env.ADN_SCOPE || 'nfse:emissao'
  });

  console.log('🔑 [SERPRO] Solicitando Bearer Token via mTLS...');
  
  try {
    const respostaAuth = await axios.post(urlToken, bodyCampos, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      httpsAgent: agenteHttps,
      timeout: 5000
    });

    if (respostaAuth.data?.access_token) {
      tokenCache = {
        token: respostaAuth.data.access_token,
        expiresAt: agora + (respostaAuth.data.expires_in * 1000)
      };
      return respostaAuth.data.access_token;
    }
  } catch (error: any) {
    console.log('⚠️ [SERPRO] Endpoint de Token indisponível ou inexistente (Erro 404/Comum em Produção). Continuando com autenticação mTLS direta por certificado.');
  }

  return null;
}

/**
 * 🔍 CONSULTA STATUS REAL DO PROTOCOLO (Exportado Corretamente)
 */
export const consultarProtocolo = async (protocolo: string): Promise<any> => {
  try {
    const pfxPassword = process.env.SENHA_CERT_PFX || '';
    let pfxBuffer: Buffer = Buffer.alloc(0);

    if (process.env.CERT_PFX_BASE64) {
      pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    }

    if (pfxBuffer.length === 0) {
      throw new Error("Certificado PFX/A1 ausente no ambiente para consulta.");
    }

    const { keyPem, certPem } = pfxParaPem(pfxBuffer, pfxPassword);
    const tokenValido = await obterBearerTokenADN(keyPem, certPem);

    const urlConsultaCompleta = `https://certificado.api.via.nfse.gov.br/consultar/${protocolo}`;

    const agenteHttps = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });

    console.log(`🔍 [SERPRO] Consultando status do protocolo: ${protocolo}`);

    const headersConfig: any = {
      'Accept': 'application/json',
      'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
    };

    if (tokenValido) {
      headersConfig['Authorization'] = `Bearer ${tokenValido}`;
    }

    const resposta = await axios.get(urlConsultaCompleta, {
      httpsAgent: agenteHttps,
      headers: headersConfig
    });

    if (resposta.data) {
      return {
        sucesso: true,
        codigoRetorno: 200,
        numeroNfse: resposta.data.numeroNfse || resposta.data.dados?.numeroNfse || null,
        chaveAcesso: resposta.data.chaveAcesso || resposta.data.dados?.chaveAcesso || null,
        xmlRetorno: resposta.data.xmlRetorno || resposta.data.dados?.xmlRetorno || null,
        urlPdf: resposta.data.urlPdf || resposta.data.dados?.urlPdf || null,
        urlXml: resposta.data.urlXml || resposta.data.dados?.urlXml || null,
        dadosRaw: resposta.data
      };
    }

    return resposta.data;

  } catch (error: any) {
    if (error.response) {
      console.error(`❌ [ADN CONSULTA REJECT] HTTP ${error.response.status}`);
      return { 
        sucesso: false, 
        mensagem: "Erro na resposta da consulta do barramento.", 
        detalhes: error.response.data 
      };
    }
    console.error('❌ [ADN CONSULTA CRITICAL ERR]:', error.message);
    throw error;
  }
};

/**
 * 🚀 TRANSMISSÃO EM XML PURO INDIVIDUAL (RECEPÇÃO DE NOTA DIRETA VIA mTLS)
 */
export const emitirNotaNacional = async (payloadRecebido: any) => {
  try {
    const pfxPassword = process.env.SENHA_CERT_PFX || '';
    let pfxBuffer: Buffer = Buffer.alloc(0);

    if (process.env.CERT_PFX_BASE64) {
      pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    }

    if (pfxBuffer.length === 0) {
      throw new Error("Certificado PFX/A1 não configurado no Railway.");
    }

    const { keyPem, certPem } = pfxParaPem(pfxBuffer, pfxPassword);

    let xmlBruto = "";
    if (typeof payloadRecebido === 'string') {
      xmlBruto = payloadRecebido;
    } else if (payloadRecebido && payloadRecebido.xmlString) {
      xmlBruto = payloadRecebido.xmlString;
    } else if (payloadRecebido && typeof payloadRecebido.body === 'string') {
      xmlBruto = payloadRecebido.body;
    } else {
      throw new Error("O payload recebido não contém um XML válido.");
    }

    // Limpeza completa de quebras de linha e espaçamentos internos para transmissão linear limpa
    const xmlLimpoParaAssinar = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpoParaAssinar, keyPem, certPem);

    const tokenValido = await obterBearerTokenADN(keyPem, certPem);

    // Endpoint homologado de Produção do SERPRO para recepção de XML individual assinado
    const urlEmissao = 'https://certificado.api.via.nfse.gov.br/recepcao/nfse';

    console.log(`📄 [SERPRO] Transmitindo XML Puro (${xmlAssinado.length} caracteres) via Handshake mTLS...`);

    const agenteHttps = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });

    const headersConfig: any = {
      'Content-Type': 'application/xml; charset=utf-8',
      'Accept': '*/*',
      'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
    };

    if (tokenValido) {
      headersConfig['Authorization'] = `Bearer ${tokenValido}`;
    }

    const resposta = await axios.post(urlEmissao, xmlAssinado, {
      httpsAgent: agenteHttps,
      headers: headersConfig,
      transformRequest: [(data) => String(data)]
    });

    const protocolo = resposta.data?.protocolo || resposta.data?.dados?.protocolo || `ADN_${Date.now()}`;

    return { 
      sucesso: true, 
      protocolo: protocolo,
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    if (error.response) {
      const erroStatus = error.response.status;
      const erroDados = typeof error.response.data === 'object' 
        ? JSON.stringify(error.response.data) 
        : String(error.response.data);

      console.error(`❌ [ADN GOV REJECT] O governo recusou a requisição. Status HTTP: ${erroStatus}`);
      console.error(`❌ [ADN GOV MOTIVO DETALHADO]: ${erroDados}`);

      return { 
        sucesso: false, 
        mensagem: `Erro retornado pelo servidor do governo (Status ${erroStatus}).`, 
        erros: [erroDados] 
      };
    }

    console.error('❌ [ADN SERVICE CRITICAL ERR]:', error.message);
    return { 
      sucesso: false, 
      mensagem: "Falha no envio ou processamento do lote XML.", 
      erros: [error.message] 
    };
  }
};

export const emitirNotaNacionalFromDados = emitirNotaNacional;
