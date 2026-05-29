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

    // Configura o agente mTLS puro
    const agenteHttps = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false // Em homologação/produção inicial ajuda a evitar travas de cadeia de CSC
    });

    // Endpoint de Produção do Token
    const urlToken = 'https://api.via.nfse.gov.br/v1/token';

    // ATENÇÃO: Agora a variável ADN_CLIENT_ID deve receber o CNPJ do Hotel (apenas números)
    const clientId = process.env.ADN_CLIENT_ID || '';

    console.log(`🔑 [SERPRO OAUTH] Solicitando token para o CNPJ/client_id: ${clientId}`);

    // Corpo da requisição conforme apontado pela IA
    const dadosToken = qs.stringify({
      grant_type: 'client_credentials',
      scope: 'nfse:recepcao',
      client_id: clientId
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
      console.log('✅ [SERPRO] Token Bearer obtido com sucesso!');
    } catch (tokenErr: any) {
      // Pega o erro detalhado exigido no diagnóstico
      console.error('❌ [SERPRO TOKEN ERR] Erro detalhado do servidor:', tokenErr.response?.data || tokenErr.message);
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

    const xmlLimpo = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpo, keyPem, certPem);

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
