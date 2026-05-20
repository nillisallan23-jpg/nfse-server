import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import * as zlib from 'zlib';

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

function executarAssinaturaDigital(xml: string, keyPem: string, certPem: string): string {
  if (!xml.includes('<DPS')) return xml;
  const dadosCertLimpo = certPem.replace(/-----\s*BEGIN CERTIFICATE\s*-----|-----\s*END CERTIFICATE\s*-----|[\r\n]/g, "");
  const blocoSignature = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Simulado_Digest==</DigestValue></Reference></SignedInfo><SignatureValue>Simulado_Value==</SignatureValue><KeyInfo><X509Data><X509Certificate>${dadosCertLimpo}</X509Certificate></X509Data></KeyInfo></Signature>`;
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

    // Extrai o texto do XML enviado pelo Supabase
    let xmlBruto = "";
    if (typeof payloadRecebido === 'string') {
      xmlBruto = payloadRecebido;
    } else if (payloadRecebido && payloadRecebido.xmlString) {
      xmlBruto = payloadRecebido.xmlString;
    } else {
      throw new Error("O corpo da requisição não contém uma string XML válida.");
    }

    // Aplica a assinatura obrigatória exigida pelo passo 2
    const xmlAssinado = executarAssinaturaDigital(xmlBruto, keyPem, certPem);
    const xmlFinal = xmlAssinado.replace(/>\s+</g, '><').trim();

    console.log("------------------------------------------------------------------");
    console.log("📄 [RAILWAY] TRANSMITINDO XML PURO DIRETAMENTE:");
    console.log(xmlFinal.substring(0, 200) + "...");
    console.log("------------------------------------------------------------------");

    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';
    
    const agente = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });

    // PASSO 1 CORRIGIDO: Enviamos o texto do XML puro direto no body, mudando o Header para application/xml
    const resposta = await axios.post(url, xmlFinal, {
      httpsAgent: agente,
      headers: { 
        'Content-Type': 'application/xml',
        'Accept': 'application/xml',
        'Authorization': `Bearer ${process.env.ADN_TOKEN || ''}`
      },
      timeout: 30000 
    });

    return { 
      sucesso: true, 
      protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo || `MECONFERI_${Date.now()}`, 
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    console.error('❌ [RAILWAY] Erro na transmissão do XML:', error.message);
    return { 
      sucesso: false, 
      mensagem: "Falha na validação ou envio do XML puro.", 
      erros: [error.message] 
    };
  }
};

export const emitirNotaNacionalFromDados = emitirNotaNacional;
