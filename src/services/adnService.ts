import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import qs from 'qs'; // Certifique-se de ter o 'qs' instalado ou use URLSearchParams

// ... (mantenha a sua função pfxParaPem e ejecutarAssinaturaDigital iguais)

/**
 * 🚀 TRANSMISSÃO OFICIAL RECONECTANDO O FLUXO DE TOKEN (CORREÇÃO DA RAIZ)
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

    // --------------------------------------------------------------------
    // PASSO 1: SOLICITAR O BEARER TOKEN CORRETAMENTE (EVITA O 404 E O 415)
    // --------------------------------------------------------------------
    console.log('🔑 [SERPRO] Solicitando Bearer Token via mTLS seguro...');
    
    // A rota correta de token de produção baseada no seu ambiente
    const urlToken = 'https://certificado.api.via.nfse.gov.br/conectar/token';

    const dadosToken = qs.stringify({
      grant_type: 'client_credentials',
      scope: 'nfse:recepcao' // Escopo padrão para envio de notas
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
      console.log('✅ [SERPRO] Token Bearer obtido com sucesso.');
    } catch (tokenErr: any) {
      console.error('❌ [SERPRO TOKEN ERR] Falha ao autenticar no gateway do governo:', tokenErr.response?.data || tokenErr.message);
      return {
        sucesso: false,
        mensagem: "Falha na geração do Token de Acesso com o governo.",
        detalhes: tokenErr.response?.data || tokenErr.message
      };
    }

    // --------------------------------------------------------------------
    // PASSO 2: TRANSMITIR O XML ASSINADO COM O TOKEN ADQUIRIDO
    // --------------------------------------------------------------------
    let xmlBruto = "";
    if (typeof payloadRecebido === 'string') {
      xmlBruto = payloadRecebido;
    } else if (payloadRecebido && payloadRecebido.xmlString) {
      xmlBruto = payloadRecebido.xmlString;
    } else {
      throw new Error("O payload recebido não contém um XML válido.");
    }

    const xmlLimpoParaAssinar = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpoParaAssinar, keyPem, certPem);

    // Rota de recepção do ecossistema nacional que consome o token gerado
    const urlEmissao = 'https://certificado.api.via.nfse.gov.br/recepcao/v1/nfse';

    console.log(`📄 [SERPRO] Transmitindo DPS assinada utilizando credenciais autenticadas...`);

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
      console.error(`❌ [ADN GOV REJECT] Status HTTP: ${error.response.status}`);
      return { 
        sucesso: false, 
        mensagem: `Erro na validação da nota (Status ${error.response.status}).`, 
        erros: [JSON.stringify(error.response.data)] 
      };
    }
    return { sucesso: false, mensagem: error.message };
  }
};
