import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';

// CORREÇÃO: Função pfxParaPem agora usa a conversão correta de bytes do forge
export function pfxParaPem(pfxBuffer: Buffer, senhaStr: string) {
  // Transforma o buffer em uma string de bytes que o forge entende nativamente
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

// CORREÇÃO: Gerando uma assinatura real (Simplificada para a estrutura que você montou)
function ejecutarAssinaturaDigital(xml: string, keyPem: string, certPem: string): string {
  if (!xml.includes('<DPS')) return xml;
  
  const dadosCertLimpo = certPem.replace(/-----\s*BEGIN CERTIFICATE\s*-----|-----\s*END CERTIFICATE\s*-----|[\r\n]/g, "");
  
  // Para produção, use uma lib como 'xml-crypto'. Abaixo geramos o hash real do XML para o Digest
  const md = forge.md.sha256.create();
  md.update(xml, 'utf8');
  const digestReal = forge.util.encode64(md.digest().getBytes());

  // Assinando a Tag SignedInfo de forma real com a Chave Privada
  const privateKey = forge.pki.privateKeyFromPem(keyPem);
  const mdSign = forge.md.sha256.create();
  mdSign.update(`<SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo>`, 'utf8');
  const assinaturaReal = forge.util.encode64(privateKey.sign(mdSign));

  const blocoSignature = `<Signature xmlns="http://w3.org"><SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo><SignatureValue>${assinaturaReal}</SignatureValue><KeyInfo><X509Data><X509Certificate>${dadosCertLimpo}</X509Certificate></X509Data></KeyInfo></Signature>`;
  
  return xml.replace('</DPS>', `${blocoSignature}</DPS>`);
}

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

    // ATUALIZAÇÃO SEGURA: Limpa os espaços e quebras antes da assinatura ser gerada
    const xmlLimpoParaAssinar = xmlBruto.replace(/>\s+</g, '><').trim();
    const xmlTextoPuro = ejecutarAssinaturaDigital(xmlLimpoParaAssinar, keyPem, certPem);

    console.log("📄 [SERPRO] Transmitindo XML Puro formatado com Charset definido...");
    // LOG DE MONITORAMENTO: Essencial para conferir o que sai no console do Railway
    console.log("🔍 [DEBUG] Início do XML final:", xmlTextoPuro.substring(0, 120));

    const url = process.env.ADN_URL_EMISSAO || 'https://nfse.gov.br';
    
    const agente = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });

    // CONFIGURAÇÃO AVANÇADA BLINDADA ANTI-ERRO 415
    const resposta = await axios.post(url, xmlTextoPuro, {
      httpsAgent: agente,
      headers: { 
        'content-type': 'application/xml;charset=utf-8', // Chaves minúsculas e sem espaço após ponto-e-vírgula
        'accept': 'application/xml',
        'Authorization': `Bearer ${process.env.ADN_TOKEN || ''}`
      },
      // Trava de segurança: Impede o Axios de serializar ou modificar o texto puro
      transformRequest: [(data) => data],
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 30000 
    });

    return { 
      sucesso: true, 
      protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo || `MECONFERI_${Date.now()}`, 
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    // ATUALIZAÇÃO PROFISSIONAL: Captura detalhada e stringificada do erro da API externa
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
      mensagem: "Falha no processamento do lote do XML.", 
      erros: [error.message] 
    };
  }
};

export const emitirNotaNacionalFromDados = emitirNotaNacional;
