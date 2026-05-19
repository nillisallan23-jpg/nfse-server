import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import * as zlib from 'zlib';

// Função utilitária interna para extrair chaves do PFX
export function pfxParaPem(pfxBuffer: Buffer, senhaStr: string) {
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, senhaStr);
  
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

// Lógica de envio e assinatura modificada para aceitar JSON ou XML em texto
export const emitirNotaNacional = async (xmlPuro: any) => {
  try {
    const pfxPassword = process.env.SENHA_CERT_PFX || '';
    let pfxBuffer: Buffer = Buffer.alloc(0);

    if (process.env.CERT_PFX_BASE64) {
      pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    }

    if (pfxBuffer.length === 0) {
      throw new Error("Certificado PFX/A1 não configurado nas variáveis de ambiente do Railway.");
    }

    // 1. Extrai as chaves PEM
    const { keyPem, certPem } = pfxParaPem(pfxBuffer, pfxPassword);

    console.log("[RAILWAY] Executando validação e preparação dos dados...");
    
    let xmlFinal = "";

    // CORREÇÃO CRÍTICA: Se o dado vier como objeto JSON do Supabase, convertemos em texto para não quebrar o .replace
    if (typeof xmlPuro === 'string') {
      xmlFinal = xmlPuro.replace(/>\s+</g, '><').trim();
    } else {
      console.log("[RAILWAY] Dados recebidos em formato de objeto. Convertendo payload...");
      xmlFinal = JSON.stringify(xmlPuro);
    }

    // 2. LOG COMPROVATÓRIO ANTES DO ENVIO
    console.log("------------------------------------------------------------------");
    console.log("📄 [DEBUG] CONTEÚDO ENVIADO AO SERPRO:");
    console.log(xmlFinal.substring(0, 300) + "...");
    console.log("------------------------------------------------------------------");

    // 3. Compactação GZIP exigida pela API
    const bufferGzip = zlib.gzipSync(xmlFinal);
    const xmlBase64 = bufferGzip.toString('base64');
    
    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';

    const payload = {
      Identificador: `MECONFERI_${Date.now()}`,
      CnpjConcessionaria: process.env.ADN_CNPJ_CONCESSIONARIA || "",
      Conteudo: xmlBase64,
      XmlGzipBase64: xmlBase64
    };

    console.log(`🚀 [SERPRO] Disparando requisição POST para: ${url}`);
    
    const agente = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });
    
    const resposta = await axios.post(url, payload, {
      httpsAgent: agente,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      timeout: 30000 
    });

    return { 
      sucesso: true, 
      protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo, 
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    console.error('❌ [RAILWAY CRÍTICO] Erro no fluxo de envio:', error.stack || error.message);
    return { 
      sucesso: false, 
      mensagem: "Falha na validação ou processamento do lote.", 
      erros: [error.message] 
    };
  }
};

// Dupla exportação para manter a compatibilidade com as rotas
export const emitirNotaNacionalFromDados = emitirNotaNacional;
