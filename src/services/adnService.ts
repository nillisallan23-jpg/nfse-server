export const emitirNotaNacional = async (xmlPuro: string) => {
  try {
    const pfxPassword = process.env.SENHA_CERT_PFX || '';
    let pfxBuffer: Buffer = Buffer.alloc(0);

    if (process.env.CERT_PFX_BASE64) {
      pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    }

    if (pfxBuffer.length === 0) {
      throw new Error("Certificado PFX/A1 não configurado nas variáveis de ambiente do Railway.");
    }

    // 1. Extrai as chaves PEM do certificado para a assinatura criptográfica
    const { keyPem, certPem } = pfxParaPem(pfxBuffer, pfxPassword);

    // 2. Executa a assinatura utilizando o xmlSignerADN
    console.log("[RAILWAY - MANUAL] Chamando módulo de assinatura para carimbar o XML...");
    
    // Certifique-se de que a sua função de assinar está sendo importada corretamente no topo do arquivo
    const xmlAssinado = assinarXmlSHA256(xmlPuro, keyPem, certPem);

    // 3. TRAVA CRÍTICA E DEFINITIVA DE SEGURANÇA (PÓS-ASSINATURA)
    if (!xmlAssinado.includes('<Signature') || !xmlAssinado.includes('<X509Certificate')) {
      console.error("❌ [BLOQUEIO MANUAL] O XML gerado não possui os elementos de assinatura digital necessários!");
      throw new Error("Falha Crítica Interna: O módulo de assinatura falhou em injetar a Signature criptográfica no XML final. Envio abortado.");
    }

    // Limpa os espaços desnecessários
    const xmlFinal = xmlAssinado.replace(/>\s+</g, '><').trim();

    // 4. LOG COMPROVATÓRIO (Roda no último milissegundo antes de disparar o HTTPS)
    console.log("------------------------------------------------------------------");
    console.log("📄 [DEBUG CRÍTICO] XML FINAL QUE SERÁ TRANSMITIDO PARA O SERPRO:");
    console.log(xmlFinal);
    console.log("------------------------------------------------------------------");

    // 5. Compactação GZIP exigida pela API ADN
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
    const agente = criarAgenteMTLS();
    
    const resposta = await axios.post(url, payload, {
      httpsAgent: agente,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      timeout: 30000 
    });

    return { sucesso: true, protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo, respostaRaw: resposta.data };

  } catch (error: any) {
    console.error('❌ [RAILWAY CRÍTICO] Erro no fluxo de envio:', error.stack || error.message);
    return { 
      sucesso: false, 
      mensagem: "Falha na validação ou assinatura do documento.", 
      erros: [error.message] 
    };
  }
};
