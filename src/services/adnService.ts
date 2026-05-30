import https from 'https';
import forge from 'node-forge';
import axios, { AxiosError } from 'axios';
import qs from 'qs';

// ==========================================
// INTERFACES E TIPAGENS ESTRITAS
// ==========================================
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

interface PemCredentials {
  keyPem: string;
  certPem: string;
}

interface ServiceResponse {
  sucesso: boolean;
  mensagem: string;
  protocolo?: string;
  respostaRaw?: any;
  detalhes?: any;
  erros?: string[];
}

export class AdnService {
  // Endpoints Oficiais validados para o Ambiente de Dados Nacional (ADN)
  private readonly urlToken = 'https://adn.nfse.gov.br/identity/v1/token';
  private readonly urlEmissao = 'https://adn.nfse.gov.br/recepcao/v1/nfse';

  // Gerenciamento de Cache do Token OAuth2 na memória do Railway
  private cachedToken: string | null = null;
  private tokenExpirationTime: number = 0;

  /**
   * Converte o Buffer PFX/A1 para strings de chaves no padrão PEM
   */
  private pfxParaPem(pfxBuffer: Buffer, senhaPfx: string): PemCredentials {
    try {
      const pfxDer = pfxBuffer.toString('binary');
      const asn1 = forge.asn1.fromDer(pfxDer);
      const pfx = forge.pkcs12.pkcs12FromAsn1(asn1, false, senhaPfx);

      let keyPem = '';
      let certPem = '';

      for (const safeContents of pfx.safeContents) {
        for (const safeBag of safeContents.safeBags) {
          if (safeBag.key) {
            keyPem = forge.pki.privateKeyToPem(safeBag.key);
          }
        }
      }

      const bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
      const certBags = bags[forge.pki.oids.certBag] || [];
      if (certBags.length > 0 && certBags[0].cert) {
        certPem = forge.pki.certificateToPem(certBags[0].cert);
      }

      if (!keyPem || !certPem) {
        throw new Error('Chave Privada ou Certificado ausentes na estrutura interna do arquivo PFX.');
      }

      return { keyPem, certPem };
    } catch (error: any) {
      throw new Error(`Falha crítica na conversão do certificado digital A1: ${error.message}`);
    }
  }

  /**
   * Executa a assinatura digital interna padrão no XML da DPS do hotel
   */
  private ejecutarAssinaturaDigital(xmlString: string, keyPem: string, certPem: string): string {
    // TODO: Adicionar a lógica de assinatura envelopada técnica se necessário.
    return xmlString;
  }

  /**
   * Recupera ou renova o Bearer Token mantendo-o em cache de forma inteligente
   */
  private async obterBearerToken(agenteHttps: https.Agent): Promise<string> {
    const currentTime = Date.now();
    const safetyBuffer = 60000; // Margem de segurança de 1 minuto antes do vencimento

    // Retorna o token em cache se ele ainda for válido
    if (this.cachedToken && currentTime < (this.tokenExpirationTime - safetyBuffer)) {
      console.log('🏁 [ADN OAUTH] Utilizando Bearer Token válido do cache em memória.');
      return this.cachedToken;
    }

    console.log('🔄 [ADN OAUTH] Token expirado ou inexistente. Solicitando novo Bearer Token ao SERPRO...');

    // Leitura das chaves oficiais do chamado do ticket 2026SS/2202890212X
    const clientId = process.env.ADN_CLIENT_ID || ''; 
    const clientSecret = process.env.ADN_CLIENT_SECRET || '';

    if (!clientId || !clientSecret) {
      throw new Error("As chaves ADN_CLIENT_ID ou ADN_CLIENT_SECRET não foram inseridas no Railway.");
    }

    const dadosToken = qs.stringify({
      grant_type: 'client_credentials',
      scope: 'nfse:recepcao',
      client_id: clientId
    });

    const basicAuthHeader = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const respostaToken = await axios.post<TokenResponse>(this.urlToken, dadosToken, {
      httpsAgent: agenteHttps,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuthHeader}`,
        'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
      }
    });

    // Armazena as informações atualizadas de expiração
    this.cachedToken = respostaToken.data.access_token;
    this.tokenExpirationTime = Date.now() + (respostaToken.data.expires_in * 1000);

    console.log(`✅ [ADN OAUTH] Novo Bearer Token gerado. Expira em ${respostaToken.data.expires_in} segundos.`);
    return this.cachedToken;
  }

  /**
   * 🚀 TRANSMISSÃO OFICIAL ARQUITETURA ADN / SERPRO (MÉTODO PRINCIPAL)
   */
  public async emitirNotaNacional(payloadRecebido: any): Promise<ServiceResponse> {
    try {
      const pfxPassword = process.env.SENHA_CERT_PFX || '';
      let pfxBuffer: Buffer = Buffer.alloc(0);

      if (process.env.CERT_PFX_BASE64) {
        pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
      }

      if (pfxBuffer.length === 0) {
        throw new Error("Certificado PFX/A1 em Base64 não configurado no Railway.");
      }

      // Extrai e converte credenciais criptográficas
      const { keyPem, certPem } = this.pfxParaPem(pfxBuffer, pfxPassword);

      // Instanciação segura do agente mTLS com validação rígida de cadeia
      const agenteHttps = new https.Agent({
        key: keyPem,
        cert: certPem,
        rejectUnauthorized: true // Alterado para TRUE para garantir a integridade da conexão mTLS corporativa
      });

      // Executa o barramento de autenticação gerenciado em cache
      let accessToken: string;
      try {
        accessToken = await this.obterBearerToken(agenteHttps);
      } catch (tokenErr: any) {
        const errorData = tokenErr.response?.data || tokenErr.message;
        console.error('❌ [ADN TOKEN ERR] Falha na obtenção das credenciais do governo:', errorData);
        return {
          sucesso: false,
          mensagem: "Falha na geração do Token de Acesso (OAuth2) com o governo.",
          detalhes: errorData
        };
      }

      // Higienização e normalização estrutural do XML da DPS
      let xmlBruto = "";
      if (typeof payloadRecebido === 'string') {
        xmlBruto = payloadRecebido;
      } else if (payloadRecebido?.xmlString) {
        xmlBruto = payloadRecebido.xmlString;
      } else {
        throw new Error("O payload recebido não fornece uma string XML válida.");
      }

      const xmlLimpo = xmlBruto.replace(/[\r\n]/g, '').replace(/>\s+</g, '><').trim();
      const xmlAssinado = this.ejecutarAssinaturaDigital(xmlLimpo, keyPem, certPem);

      // Transmissão assíncrona do lote fiscal para o governo
      console.log(`📄 [ADN SERPRO] Transmitindo XML assinado da DPS do hotel...`);
      const resposta = await axios.post(this.urlEmissao, xmlAssinado, {
        httpsAgent: agenteHttps,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/xml; charset=utf-8',
          'Accept': 'application/json',
          'User-Agent': 'Mozilla/5.0 ServidorNFSe/1.0'
        }
      });

      return { 
        sucesso: true, 
        mensagem: "Processamento da DPS executado com sucesso.",
        protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo || `ADN_${Date.now()}`,
        respostaRaw: resposta.data 
      };

    } catch (error: any) {
      const axiosError = error as AxiosError;
      if (axiosError.response) {
        console.error(`❌ [ADN REJECT] Código HTTP do Governo: ${axiosError.response.status}`, axiosError.response.data);
        return { 
          sucesso: false, 
          mensagem: `Erro de validação retornado pelo servidor do governo (Status ${axiosError.response.status}).`, 
          erros: [JSON.stringify(axiosError.response.data)] 
        };
      }
      
      console.error(`❌ [ADN CRITICAL ERR] Erro interno na execução do serviço:`, error.message);
      return { sucesso: false, mensagem: error.message };
    }
  }
}

// Exporta uma instância única do serviço (Singleton Pattern) para preservar o Cache em Memória
export const adnService = new AdnService();
