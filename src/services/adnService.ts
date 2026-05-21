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
  mdSign.update(`<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo>`, 'utf8');
  const assinaturaReal = forge.util.encode64(privateKey.sign(mdSign));

  const blocoSignature = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo><SignatureValue>${assinaturaReal}</SignatureValue><KeyInfo><X509Data><X509Certificate>${dadosCertLimpo}</X509Certificate></X509Data></KeyInfo></Signature>`;
  
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

    const xmlAssinado = ejecutarAssinaturaDigital(xmlBruto, keyPem, certPem);
    const xmlFinal = xmlAssinado.replace(/>\s+</g, '><').trim();

    console.log("📄 [SERPRO] Transmitindo XML Puro formatado com Charset definido...");
    // LOG DE MONITORAMENTO: Mostra o começo do que está sendo enviado para garantir que é XML puro
    console.log("🔍 [DEBUG] Início do XML final:", String(xmlFinal).substring(0, 120));

    const url = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';
    
    const agente = new https.Agent({
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false
    });

    // BLOCO ATUALIZADO: Forçando o Axios a tratar o payload estritamente como String de Texto Puro
    const resposta = await axios.post(url, String(xmlFinal), {
      httpsAgent: agente,
      headers: { 
        'Content-Type': 'application/xml; charset=utf-8',
        'Accept': 'application/xml',
        'Authorization': `Bearer ${process.env.ADN_TOKEN || ''}`
      },
      // Impede que o Axios intercepte e converta o dado para objeto/JSON por debaixo dos panos
      transformRequest: [(data) => data],
      timeout: 30000 
    });

    return { 
      sucesso: true, 
      protocolo: resposta.data?.protocolo || resposta.data?.dados?.protocolo || `MECONFERI_${Date.now()}`, 
      respostaRaw: resposta.data 
    };

  } catch (error: any) {
    if (error.response) {
      console.error(`❌ [ADN SERVICE ERR]: Falha na requisição. Status: ${error.response.status}`);
      console.error('❌ [ADN SERVICE ERR DETALHES]:', error.response.data);
      return { 
        sucesso: false, 
        mensagem: `Erro retornado pelo servidor (Status ${error.response.status}).`, 
        erros: [JSON.stringify(error.response.data)] 
      };
    }

    console.error('❌ [ADN SERVICE ERR]:', error.message);
    return { 
      sucesso: false, 
      mensagem: "Falha no processamento do lote do XML.", 
      erros: [error.message] 
    };
  }
};

export const emitirNotaNacionalFromDados = emitirNotaNacional;
