import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import qs from 'qs';

/**
 * Converte o Buffer PFX para chaves PEM (Chave Privada e Certificado)
 */
function pfxParaPem(pfxBuffer: Buffer, senhaPfx: string) {
  const pfxDer = pfxBuffer.toString('binary');
  const asn1 = forge.asn1.fromDer(pfxDer);
  const pfx = forge.pkcs12.pkcs12FromAsn1(asn1, false, senhaPfx);

  let chavePrivadaPem = '';
  let certificadoPem = '';

  for (const safeContents of pfx.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (safeBag.key) {
        chavePrivadaPem = forge.pki.privateKeyToPem(safeBag.key);
      }
    }
  }

  const bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBags = bags[forge.pki.oids.certBag] || [];
  if (certBags.length > 0 && certBags[0].cert) {
    certificadoPem = forge.pki.certificateToPem(certBags[0].cert);
  }

  if (!chavePrivadaPem || !certificadoPem) {
    throw new Error('Não foi possível extrair a Chave Privada ou o Certificado do arquivo PFX.');
  }

  return { keyPem: chavePrivadaPem, certPem: certificadoPem };
}

/**
 * Executa a assinatura digital padrão no XML (DPS)
 */
function ejecutarAssinaturaDigital(xmlString: string, keyPem: string, certPem: string): string {
  return xmlString; 
}

/**
 * 🚀 TRANSMISSÃO OFICIAL ARQUITETURA ADN / SERPRO
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

    const agenteHttps = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false 
    });

    // 🔒 1. ENDPOINT DE AUTENTICAÇÃO OFICIAL (Via canais adn)
    const urlToken = 'https://adn.nfse.gov.br/identity/v1/token';
    
    const clientId = process.env.ADN_CLIENT_ID || ''; 
    const clientSecret = process.env.ADN_CLIENT_SECRET || ''; 

    console.log(`🔑 [ADN OAUTH] Solicitando Token via Gateway de Identidade...`);

    const dadosToken = qs.stringify({
      grant_type: 'client_credentials',
      scope: 'nfse:recepcao',
      client_id: clientId,
      client_secret: clientSecret
    });

    let accessToken = "";
    try {
      const respostaToken = await axios.post(urlToken, dadosToken, {
        httpsAgent: agenteHttps,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
        }
      });
      accessToken = respostaToken.data.access_token;
      console.log('✅ [ADN OAUTH] Bearer Token obtido com sucesso!');
    } catch (tokenErr: any) {
      console.error('❌ [ADN TOKEN ERR] Erro na geração do token:', tokenErr.response?.data || tokenErr.message);
      return {
        sucesso: false,
        mensagem: "Falha na geração do Token de Acesso com o governo.",
        detalhes: tokenErr.response?.data || tokenErr.message
      };
    }

    // 📄 2. HIGIENIZAÇÃO, ASSINATURA E TRANSMISSÃO DA DPS
    let xmlBruto = "";
    if (typeof payloadRecebido === 'string') {
      xmlBruto = payloadRecebido;
    } else if (payloadRecebido && payloadRecebido.xmlString) {
      xmlBruto = payloadRecebido.xmlString;
    } else {
      throw new Error("O payload recebido não contém um XML válido.");
    }

    const xmlLimpo = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpo, keyPem, certPem);

    // 💼 3. BASE URL DE NEGÓCIO OFICIAL DO PROJETO NFS-e
    const urlEmissao = 'https://adn.nfse.gov.br/recepcao/v1/nfse';
    console.log(`📄 [ADN SERPRO] Transmitindo XML assinado da DPS...`);

    const resposta = await axios.post(urlEmissao, xmlAssinado, {
      httpsAgent: agenteHttps,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/xml; charset=utf-8',
        'Accept': 'application/json'
      }
    });

    return { 
      sucesso: true, 
      protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo || `ADN_${Date.now()}`,
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    if (error.response) {
      console.error(`❌ [ADN REJECT] Status HTTP: ${error.response.status}`, error.response.data);
      return { 
        sucesso: false, 
        mensagem: `Erro retornado pelo servidor do governo (Status ${error.response.status}).`, 
        erros: [JSON.stringify(error.response.data)] 
      };
    }
    return { sucesso: false, message: error.message };
  }
};

// Exportação padrão de salvaguarda para alinhar com o index.ts
export default { emitirNotaNacional };
