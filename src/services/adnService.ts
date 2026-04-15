import axios from 'axios';
import https from 'https';
import fs from 'fs';
import zlib from 'zlib';
import { promisify } from 'util';

const gzip = promisify(zlib.gzip);

/**
 * Interface para o resultado da emissão no padrão ADN
 */
export interface ResultadoADN {
  sucesso: boolean;
  mensagem: string;
  protocolo?: string;
  chaveAcesso?: string;
  erros?: any[];
  respostaRaw?: any;
}

/**
 * FUNÇÃO PRINCIPAL: Envia a nota para o Ambiente Nacional (Serpro)
 * Esta função substitui toda a complexidade de SOAP, XML Signer e XML Builder.
 */
export const emitirNotaNacional = async (xmlString: string): Promise<ResultadoADN> => {
  try {
    console.log('📦 Iniciando pipeline ADN: GZip -> Base64 -> mTLS');

    // 1. Compactar o XML com GZip (Requisito do Governo)
    const bufferXml = Buffer.from(xmlString, 'utf-8');
    const gzippedBuffer = await gzip(bufferXml);
    
    // 2. Converter para Base64
    const xmlBase64Gzip = gzippedBuffer.toString('base64');

    // 3. Montar o JSON conforme o padrão ADN (RecepcaoDocumentoRequest)
    const cnpj = process.env.ADN_CNPJ_CONCESSIONARIA || '';
    const payload = {
      cnpjConcessionaria: cnpj.replace(/\D/g, ''), // Remove pontos e traços
      identificador: `ENVIO_${Date.now()}`,
      notaFiscalViaXmlGZipBase64: xmlBase64Gzip
    };

    // 4. Configurar Agente mTLS com o Certificado Digital (.pfx)
    // O Railway lê o arquivo do caminho definido na variável de ambiente
    const httpsAgent = new https.Agent({
      pfx: fs.readFileSync(process.env.CERT_PFX_PATH!),
      passphrase: process.env.SENHA_CERT_PFX,
    });

    // 5. Definir URL (Usa a de homologação restrita por padrão)
    const url = process.env.ADN_URL_EMISSAO || 'https://producaorestrita.certificado.api.via.nfse.gov.br/recepcao/v1/nfsev';

    console.log(`🌐 Enviando para o Ambiente Nacional: ${url}`);

    const response = await axios.post(url, payload, {
      httpsAgent,
      timeout: 60000,
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    console.log('✅ Resposta recebida do Governo com sucesso!');

    return {
      sucesso: true,
      mensagem: 'Nota processada com sucesso!',
      protocolo: response.data?.protocolo || response.data?.id,
      chaveAcesso: response.data?.chaveAcesso,
      respostaRaw: response.data
    };

  } catch (error: any) {
    const status = error.response?.status || 'N/A';
    const erroDados = error.response?.data;

    console.error(`❌ Erro na integração ADN (HTTP ${status}):`, erroDados || error.message);

    return {
      sucesso: false,
      mensagem: erroDados?.mensagem || erroDados?.message || 'Erro ao comunicar com API Nacional.',
      erros: erroDados?.erros || [error.message],
      respostaRaw: erroDados
    };
  }
};