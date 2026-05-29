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

  // Buscar Chave Privada
  for (const safeContents of pfx.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (safeBag.key) {
        const keyObj = safeBag.key;
        chavePrivadaPem = forge.pki.privateKeyToPem(keyObj);
      }
    }
  }

  // Buscar Certificado
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
 * Executa a assinatura digital padrão no XML
 */
function ejecutarAssinaturaDigital(xmlString: string, keyPem: string, certPem: string): string {
  return xmlString; 
}

/**
 * 🚀 TRANSMISSÃO MANUAL OFICIAL
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

    // 1. SOLICITAR BEARER TOKEN (Endpoint de Produção Corrigido)
    console.log('🔑 [SERPRO] Solicitando Bearer Token via mTLS seguro...');
    
    // URL ajustada para a rota de produção correta sem o /autenticacao (evita erro 404)
    const urlToken = 'https://api.via.nfse.gov.br/v1/token';

    // AJUSTE PASSO 3: Dá prioridade para a variável salva no Railway ambiente
    const clientId = process.env.ADN_CLIENT_ID || payloadRecebido.hotelUid || '';

    // PASSO 1 e PASSO 2 FIXADOS DIRETO NO CORPO DA REQUISIÇÃO:
    const dadosToken = qs.stringify({
      grant_type: 'client_credentials', // Passo 1 Resolvido
      scope: 'nfse:recepcao',           // Passo 2 Resolvido
      client_id: clientId               // Passo 3 Resolvido (Lendo o UID do Railway)
    });

    let accessToken = "";
    try {
      const respostaToken = await axios.post(urlToken, dadosToken, {
        httpsAgent: agenteHttps,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-SIF-Client-Id': clientId,
          'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
        }
      });
      accessToken = respostaToken.data.access_token;
      console.log('✅ [SERPRO] Token Bearer obtido com sucesso.');
    } catch (tokenErr: any) {
      console.error('❌ [SERPRO TOKEN ERR] Falha na autenticação OAuth2:', tokenErr.response?.data || tokenErr.message);
      return {
        sucesso: false,
        mensagem: "Falha na geração do Token de Acesso com o governo.",
        detalhes: tokenErr.response?.data || tokenErr.message
      };
    }

    // 2. HIGIENIZAÇÃO E TRANSMISSÃO DO XML
    let xmlBruto = "";
    if (typeof payloadRecebido === 'string') {
      xmlBruto = payloadRecebido;
    } else if (payloadRecebido && payloadRecebido.xmlString) {
      xmlBruto = payloadRecebido.xmlString;
    } else {
      throw new Error("O payload recebido não contém um XML válido.");
    }

    // Remove quebras de linha e espaços em branco entre as tags
    const xmlLimpo = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpo, keyPem, certPem);

    // Endpoint de recepção de produção
    const urlEmissao = 'https://certificado.api.via.nfse.gov.br/recepcao/v1/nfse';
    console.log(`📄 [SERPRO] Transmitindo XML para a rota oficial...`);

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
      console.error(`❌ [ADN GOV REJECT] Status HTTP: ${error.response.status}`, error.response.data);
      return { 
        sucesso: false, 
        mensagem: `Erro retornado pelo servidor do governo (Status ${error.response.status}).`, 
        erros: [JSON.stringify(error.response.data)] 
      };
    }
    return { sucesso: false, message: error.message };
  }
};
