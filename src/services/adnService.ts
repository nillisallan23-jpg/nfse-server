import axios from 'axios';
import * as https from 'https';
import * as fs from 'fs';
import * as zlib from 'zlib';
import { promisify } from 'util';
import * as forge from 'node-forge';

const gzip = promisify(zlib.gzip);

export interface AdnEmissionResponse {
  sucesso: boolean;
  mensagem: string;
  protocolo?: string;
  chaveAcesso?: string;
  erros?: any[];
  respostaRaw?: any;
}

interface PemMaterial {
  keyPem: string;
  certPem: string;
  caPem?: string;
}

/**
 * Converte um PFX (.pfx/.p12) — inclusive os "legacy" gerados com RC2/3DES —
 * em PEM (chave + certificado + CA chain) usando node-forge puro em JS.
 *
 * Isso evita o erro "mac verify failure" / "unsupported" do OpenSSL 3
 * que afeta PFX antigos quando lidos diretamente pelo https.Agent.
 */
function pfxParaPem(pfxBuffer: Buffer, senha: string): PemMaterial {
  // node-forge precisa do conteúdo binário em string "binary"
  const pfxBinary = pfxBuffer.toString('binary');
  const p12Asn1 = forge.asn1.fromDer(pfxBinary);

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    // Tenta com a senha fornecida
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
  } catch (e1: unknown) {
    try {
      // Alguns PFX usam senha vazia mesmo quando uma é informada
      p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, '');
    } catch (e2: unknown) {
      const msg = e1 instanceof Error ? e1.message : String(e1);
      throw new Error(
        `Falha ao abrir o PFX (mac verify failure). Verifique a SENHA_CERT_PFX. Detalhe: ${msg}`
      );
    }
  }

  // ── Chave privada ───────────────────────────────────────
  const keyBags =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
      forge.pki.oids.pkcs8ShroudedKeyBag
    ] ||
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];

  if (!keyBags || keyBags.length === 0 || !keyBags[0].key) {
    throw new Error('Chave privada não encontrada no PFX.');
  }
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);

  // ── Certificados (cliente + cadeia ICP-Brasil) ──────────
  const certBags =
    p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];

  if (certBags.length === 0 || !certBags[0].cert) {
    throw new Error('Certificado não encontrado no PFX.');
  }

  // Identifica o certificado de entidade final (end-entity) e a cadeia (CAs)
  const allCerts = certBags
    .filter((b) => b.cert)
    .map((b) => b.cert!);

  console.log(`🔗 Cadeia de certificados encontrada no PFX: ${allCerts.length} certificado(s)`);

  // Loga cada certificado da cadeia para debug
  allCerts.forEach((cert, idx) => {
    const cn = cert.subject.getField('CN')?.value || 'sem CN';
    const issuer = cert.issuer.getField('CN')?.value || 'sem issuer';
    const isSelfSigned = cn === issuer;
    console.log(
      `   [${idx}] CN: "${cn}" | Issuer: "${issuer}"${isSelfSigned ? ' (ROOT/self-signed)' : ''}`
    );
  });

  // O certificado de entidade final é aquele que NÃO é auto-assinado
  let endEntityIdx = 0;
  for (let i = 0; i < allCerts.length; i++) {
    const c = allCerts[i];
    const cn = c.subject.getField('CN')?.value;
    const issuerCn = c.issuer.getField('CN')?.value;
    if (cn !== issuerCn) {
      endEntityIdx = i;
      break;
    }
  }

  const endEntityCert = allCerts[endEntityIdx];
  const certPem = forge.pki.certificateToPem(endEntityCert);

  // Cadeia = todos os outros certificados (intermediários + raiz)
  const chainCerts = allCerts.filter((_, idx) => idx !== endEntityIdx);
  let caPem = chainCerts.map((c) => forge.pki.certificateToPem(c)).join('\n');

  // ── Diagnóstico de CERT_CHAIN_BASE64 ─────────────────────
  const rawChainEnv = process.env.CERT_CHAIN_BASE64;
  const chainPresente = !!(rawChainEnv && rawChainEnv.trim().length > 0);
  console.log(
    `🔍 Verificando variável: CERT_CHAIN_BASE64 está presente? ${chainPresente ? 'Sim' : 'Não'}`
  );
  if (chainPresente) {
    const preview = rawChainEnv!.trim().substring(0, 10);
    console.log(`🔍 Primeiros 10 caracteres de CERT_CHAIN_BASE64: "${preview}..."`);
    console.log(`🔍 Tamanho total da variável: ${rawChainEnv!.length} chars`);
  }

  // PRIORIDADE TOTAL: se CERT_CHAIN_BASE64 está definida, ela SOBRESCREVE a cadeia do PFX.
  if (chainPresente) {
    try {
      // Limpeza: trim + remoção de quebras de linha (Windows \r\n e Unix \n) e espaços
      const cleanedBase64 = rawChainEnv!
        .trim()
        .replace(/[\r\n\s]/g, '');
      const chainBuffer = Buffer.from(cleanedBase64, 'base64');
      const chainPemFromEnv = chainBuffer.toString('utf-8');
      const matches = chainPemFromEnv.match(/-----BEGIN CERTIFICATE-----/g);
      const count = matches?.length || 0;

      if (count === 0) {
        console.error(
          '❌ CERT_CHAIN_BASE64 decodificada mas não contém certificados PEM válidos.'
        );
      } else {
        // FORÇA o uso da cadeia da variável de ambiente (PRIORIDADE TOTAL)
        caPem = chainPemFromEnv;
        console.log(
          `✅ Cadeia ICP-Brasil carregada de CERT_CHAIN_BASE64 (${count} certificado(s)) — PRIORIDADE TOTAL ativa`
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('❌ Falha ao decodificar CERT_CHAIN_BASE64:', msg);
    }
  } else if (chainCerts.length === 0) {
    console.warn(
      '⚠️  PFX não contém intermediários e CERT_CHAIN_BASE64 não definida. Handshake mTLS pode falhar com HTTP 495.'
    );
  } else {
    console.log(`✅ ${chainCerts.length} certificado(s) intermediário(s) extraído(s) do PFX.`);
  }

  const cn = endEntityCert.subject.getField('CN')?.value || 'desconhecido';
  console.log(`🔐 Certificado de entidade final: CN="${cn}"`);

  return { keyPem, certPem, caPem: caPem || undefined };
}

/**
 * Cria o agente HTTPS com mTLS. Usa PEM (gerado a partir do PFX via node-forge),
 * que funciona em qualquer versão do OpenSSL/Node sem precisar de flags legacy.
 */
function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH;
  const pfxPassword = process.env.SENHA_CERT_PFX || process.env.CERT_PFX_PASSWORD || '';

  let pfxBuffer: Buffer;

  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    console.log(`🔐 Certificado carregado via CERT_PFX_BASE64 (${pfxBuffer.length} bytes)`);
  } else {
    if (!pfxPath) {
      throw new Error('Variável CERT_PFX_PATH não definida.');
    }
    if (!fs.existsSync(pfxPath)) {
      throw new Error(`Certificado não encontrado em: ${pfxPath}`);
    }
    // Leitura como buffer binário puro — sem encoding
    pfxBuffer = fs.readFileSync(pfxPath);
    console.log(`🔐 Certificado carregado do disco: ${pfxPath} (${pfxBuffer.length} bytes)`);
  }

  // Converte PFX → PEM (resolve mac verify failure no OpenSSL 3)
  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

  // Split CA bundle em array (Node aceita melhor múltiplos certificados assim)
  const caArray = caPem
    ? caPem
        .split(/(?=-----BEGIN CERTIFICATE-----)/g)
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
    : undefined;

  if (caArray && caArray.length > 0) {
    console.log(`🔐 Agente HTTPS configurado com ${caArray.length} CA(s) na cadeia.`);
  } else {
    console.warn('⚠️  Agente HTTPS sem CA chain — handshake pode falhar (HTTP 495).');
  }

  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized: process.env.ADN_AMBIENTE === 'producao',
  });
}

/**
 * Emite uma NFS-e no padrão ADN/Serpro Nacional.
 *
 * Pipeline: XML → GZIP → Base64 → JSON → POST mTLS → Resposta
 */
export const emitirNotaNacional = async (xmlString: string): Promise<AdnEmissionResponse> => {
  try {
    // ── 1. Compactar o XML com GZip ───────────────────────
    const bufferXml = Buffer.from(xmlString, 'utf-8');
    const gzippedBuffer = await gzip(bufferXml);
    console.log(`📦 XML compactado: ${bufferXml.length} bytes → GZIP ${gzippedBuffer.length} bytes`);

    // ── 2. Converter para Base64 ──────────────────────────
    const xmlBase64Gzip = gzippedBuffer.toString('base64');

    // ── 3. Montar JSON (RecepcaoDocumentoRequest) ─────────
    const cnpj = process.env.ADN_CNPJ_CONCESSIONARIA || process.env.PRESTADOR_CNPJ;
    if (!cnpj) {
      throw new Error('CNPJ não configurado (ADN_CNPJ_CONCESSIONARIA ou PRESTADOR_CNPJ).');
    }

    const idSolicitacao = `ENVIO_${Date.now()}`;
    const payload = {
      cnpjConcessionaria: cnpj.replace(/\D/g, ''),
      identificador: idSolicitacao,
      notaFiscalViaXmlGZipBase64: xmlBase64Gzip,
    };

    console.log(
      `📋 Payload — CNPJ: ${payload.cnpjConcessionaria} | ID: ${payload.identificador} | Base64: ${xmlBase64Gzip.length} chars`
    );

    // ── 4. Configurar agente mTLS ─────────────────────────
    const httpsAgent = criarAgenteMTLS();

    // ── 5. Enviar para o Ambiente Nacional (ADN/Serpro) ────
    const url =
      process.env.ADN_URL_EMISSAO ||
      (process.env.ADN_AMBIENTE === 'producao'
        ? process.env.ADN_URL_PRODUCAO
        : process.env.ADN_URL_HOMOLOGACAO) ||
      'https://sefin.nfse.gov.br/sefinnacional/nfse';

    console.log(`🌐 Enviando para ${url}...`);

    const response = await axios.post(url, payload, {
      httpsAgent,
      timeout: 60_000,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
    });

    console.log(`✅ Resposta ADN: HTTP ${response.status}`);

    return {
      sucesso: true,
      mensagem: 'Nota enviada com sucesso!',
      protocolo: response.data?.protocolo || response.data?.id || idSolicitacao,
      chaveAcesso: response.data?.chaveAcesso,
      respostaRaw: response.data,
    };
  } catch (error: unknown) {
    const err = error as { response?: { status?: number; data?: any }; message?: string };
    const status = err.response?.status || 'N/A';
    const body = err.response?.data;

    console.error(`❌ Erro na integração ADN (HTTP ${status}):`, body || err.message);

    return {
      sucesso: false,
      mensagem:
        body?.message ||
        body?.mensagem ||
        err.message ||
        'Erro ao processar envio nacional.',
      erros: body?.erros || (body ? [body] : undefined),
      respostaRaw: body,
    };
  }
};
