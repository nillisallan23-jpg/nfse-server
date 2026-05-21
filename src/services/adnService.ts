import fs from 'fs';
import https from 'https';
import forge from 'node-forge';

export function pfxParaPem(pfxBuffer: Buffer, senhaStr: string) {
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

function ejecutarAssinaturaDigital(xml: string, keyPem: string, certPem: string): string {
  if (!xml.includes('<DPS')) return xml;
  
  const dadosCertLimpo = certPem.replace(/-----\s*BEGIN CERTIFICATE\s*-----|-----\s*END CERTIFICATE\s*-----|[\r\n]/g, "");
  
  const md = forge.md.sha256.create();
  md.update(xml, 'utf8');
  const digestReal = forge.util.encode64(md.digest().getBytes());

  const privateKey = forge.pki.privateKeyFromPem(keyPem);
  const mdSign = forge.md.sha256.create();
  mdSign.update(`<SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo>`, 'utf8');
  const assinaturaReal = forge.util.encode64(privateKey.sign(mdSign));

  const blocoSignature = `<Signature xmlns="http://w3.org"><SignedInfo><SignatureMethod Algorithm="http://w3.org"/><Reference URI=""><Transforms><Transform Algorithm="http://w3.org"/></Transforms><DigestMethod Algorithm="http://w3.org"/><DigestValue>${digestReal}</DigestValue></Reference></SignedInfo><SignatureValue>${assinaturaReal}</SignatureValue><KeyInfo><X509Data><X509Certificate>${dadosCertLimpo}</X509Certificate></X509Data></KeyInfo></Signature>`;
  
  return xml.replace('</DPS>', `${blocoSignature}</DPS>`);
}

function dispararRequisicaoNativaHttps(urlCompleta: string, payload: string, options: https.RequestOptions): Promise<{ status: number; data: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(urlCompleta, options, (res) => {
      let dadosResposta = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { dadosResposta += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, data: dadosResposta });
      });
    });
    req.on('error', (err) => { reject(err); });
    req.write(payload);
    req.end();
  });
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

    // 1. Limpa e Assina o XML da DPS enviado pelo Lovable/Supabase
    const xmlLimpoParaAssinar = xmlBruto.replace(/>\s+</g, '><').trim();
    const xmlAssinado = ejecutarAssinaturaDigital(xmlLimpoParaAssinar, keyPem, certPem);

    // 2. 💎 ESTRATÉGIA CRUCIAL: Envelopamento SOAP 1.2 exigido pelo SERPRO/ADN
    // O seu XML assinado entra de forma pura dentro da tag de requisição correspondente
    const soapEnvelope = 
`<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <EnviarLoteRpsEnvio xmlns="http://www.nfse.gov.br/Schema/nfse_v1.00.xsd">
      ${xmlAssinado.replace('<?xml version="1.0" encoding="UTF-8"?>', '')}
    </EnviarLoteRpsEnvio>
  </soap12:Body>
</soap12:Envelope>`;

    console.log("📄 [SERPRO] Transmitindo Lote via Envelope SOAP 1.2...");
    console.log("🔍 [DEBUG] Amostra do Payload SOAP de Saída:", soapEnvelope.substring(0, 200));

    const urlEmissao = process.env.ADN_URL_EMISSAO || 'https://certificado.api.via.nfse.gov.br/recepcao/nfsev';
    const tokenValido = String(process.env.ADN_TOKEN || '').trim();

    // Alteração de Content-Type para o padrão aceito por Web Services Governamentais SOAP
    const opcoesRequisicao: https.RequestOptions = {
      method: 'POST',
      key: keyPem,
      cert: certPem,
      rejectUnauthorized: false,
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'Accept': 'application/soap+xml, application/xml, text/xml',
        'Authorization': `Bearer ${tokenValido}`,
        'Content-Length': Buffer.byteLength(soapEnvelope, 'utf8'),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebServNFSe/1.0'
      }
    };

    const resposta = await dispararRequisicaoNativaHttps(urlEmissao, soapEnvelope, opcoesRequisicao);

    if (resposta.status >= 200 && resposta.status < 300) {
      return { 
        sucesso: true, 
        respostaRaw: resposta.data 
      };
    }

    throw {
      isNativeAxiosEquivalent: true,
      response: {
        status: resposta.status,
        data: resposta.data
      }
    };

  } catch (error: any) {
    if (error.response || error.isNativeAxiosEquivalent) {
      const targetResponse = error.response || error;
      const erroStatus = targetResponse.status;
      const erroDados = typeof targetResponse.data === 'object' 
        ? JSON.stringify(targetResponse.data) 
        : String(targetResponse.data);

      console.error(`❌ [ADN GOV REJECT] O governo recusou a requisição. Status HTTP: ${erroStatus}`);
      console.error(`❌ [ADN GOV MOTIVO DETALHADO]: ${erroDados || '(Corpo vazio)'}`);

      return { 
        sucesso: false, 
        mensagem: `Erro retornado pelo servidor do governo (Status ${erroStatus}).`, 
        erros: [erroDados || 'Resposta de mídia vazia'] 
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
