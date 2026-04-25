Vou aplicar todas as 5 melhorias de auditoria no `adnService.ts`
 0 ? 'Sim' : 'NÃO'} | ` +\\n      `Caracteres: ${senhaLen} | ` +\\n      `Tipo: ${typeof senha}`\\n  );\\n  if (senhaLen === 0) {\\n    console.warn(\\n      '⚠️  SENHA VAZIA detectada — node-forge tentará abrir o PFX sem senha. ' +\\n        'Confirme que SENHA_CERT_PFX está configurada corretamente no Railway.'\\n    );\\n  }\\n\\n  // node-forge precisa do conteúdo binário em string \\\"binary\\\"\\n  const pfxBinary = pfxBuffer.toString('binary');\\n\\n  let p12Asn1: forge.asn1.Asn1;\\n  try {\\n    p12Asn1 = forge.asn1.fromDer(pfxBinary);\\n    console.log(`✅ PFX decodificado em ASN.1 com sucesso (${pfxBuffer.length} bytes).`);\\n  } catch (errAsn1: unknown) {\\n    const msg = errAsn1 instanceof Error ? errAsn1.message : String(errAsn1);\\n    console.error(`❌ FALHA ASN.1: o arquivo PFX parece corrompido ou não é DER válido. Detalhe: ${msg}`);\\n    throw new Error(`PFX corrompido ou formato inválido: ${msg}`);\\n  }\\n\\n  let p12: forge.pkcs12.Pkcs12Pfx;\\n  try {\\n    // Tenta com a senha fornecida\\n    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);\\n    console.log('✅ PFX aberto com sucesso usando SENHA_CERT_PFX.');\\n  } catch (e1: unknown) {\\n    const msg1 = e1 instanceof Error ? e1.message : String(e1);\\n    console.error(`⚠️  Tentativa 1 (com senha de ${senhaLen} chars) FALHOU: \\\"${msg1}\\\"`);\\n\\n    try {\\n      // Alguns PFX usam senha vazia mesmo quando uma é informada\\n      p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, '');\\n      console.log('✅ PFX aberto com SENHA VAZIA (a senha configurada estava errada).');\\n    } catch (e2: unknown) {\\n      const msg2 = e2 instanceof Error ? e2.message : String(e2);\\n      console.error(`❌ Tentativa 2 (senha vazia) também FALHOU: \\\"${msg2}\\\"`);\\n      console.error(\\n        '🚨 DIAGNÓSTICO: A senha do certificado está incorreta OU o arquivo PFX está corrompido.\\\\n' +\\n          '   • Verifique SENHA_CERT_PFX no Railway (cuidado com espaços e quebras de linha)\\\\n' +\\n          '   • Reexporte o PFX do certificado original e atualize CERT_PFX_BASE64'\\n      );\\n      throw new Error(\\n        `Falha ao abrir o PFX (mac verify failure). Senha incorreta ou arquivo corrompido. Detalhe: ${msg1}`\\n      );\\n    }\\n  }\"}">

 {\\n    const cn = cert.subject.getField('CN')?.value || 'sem CN';\\n    const issuer = cert.issuer.getField('CN')?.value || 'sem issuer';\\n    const isSelfSigned = cn === issuer;\\n    console.log(\\n      `   [${idx}] CN: \\\"${cn}\\\" | Issuer: \\\"${issuer}\\\"${isSelfSigned ? ' (ROOT/self-signed)' : ''}`\\n    );\\n  });\", \"first_replaced_line\": 80, \"last_replaced_line\": 90, \"replace\": \"  console.log(`🔗 ═══ CADEIA DE CERTIFICADOS DO PFX (${allCerts.length} cert) ═══`);\\n\\n  // Loga cada certificado da cadeia com detalhes completos\\n  allCerts.forEach((cert, idx) => {\\n    const cn = cert.subject.getField('CN')?.value || 'sem CN';\\n    const o = cert.subject.getField('O')?.value || 'sem O';\\n    const ou = cert.subject.getField('OU')?.value || 'sem OU';\\n    const issuerCn = cert.issuer.getField('CN')?.value || 'sem issuer';\\n    const issuerO = cert.issuer.getField('O')?.value || 'sem issuer-O';\\n    const isSelfSigned = cn === issuerCn;\\n    const validFrom = cert.validity.notBefore.toISOString().substring(0, 10);\\n    const validTo = cert.validity.notAfter.toISOString().substring(0, 10);\\n    const serial = cert.serialNumber?.substring(0, 16) || 'sem serial';\\n    const expirado = cert.validity.notAfter < new Date();\\n\\n    console.log(`   ┌─ [${idx}] ${isSelfSigned ? '🔒 ROOT (self-signed)' : '📄 CERT'}`);\\n    console.log(`   │  Subject CN : \\\"${cn}\\\"`);\\n    console.log(`   │  Subject O  : \\\"${o}\\\" | OU: \\\"${ou}\\\"`);\\n    console.log(`   │  Issuer  CN : \\\"${issuerCn}\\\"`);\\n    console.log(`   │  Issuer  O  : \\\"${issuerO}\\\"`);\\n    console.log(`   │  Validade   : ${validFrom} → ${validTo}${expirado ? ' ⚠️  EXPIRADO!' : ' ✅'}`);\\n    console.log(`   └─ Serial    : ${serial}...`);\\n  });\\n  console.log(`🔗 ═══════════════════════════════════════════════════════`);\"}">

 50000) {\\n      console.warn(`⚠️  PFX muito grande (${stats.size} bytes) — verifique se não é o arquivo errado.`);\\n    }\\n\\n    // Leitura como buffer binário puro — sem encoding\\n    pfxBuffer = fs.readFileSync(pfxPath);\\n    console.log(`🔐 Certificado carregado do disco: ${pfxPath} (${pfxBuffer.length} bytes lidos)`);\\n\\n    // Confere o \\\"magic byte\\\" do DER (0x30 = SEQUENCE ASN.1)\\n    if (pfxBuffer[0] !== 0x30) {\\n      console.warn(\\n        `⚠️  Primeiro byte = 0x${pfxBuffer[0].toString(16)} (esperado 0x30). ` +\\n          'O arquivo pode não ser um PFX/DER válido — talvez esteja em base64?'\\n      );\\n    }\\n  }\"}">

 0) {\\n    console.log(`🔐 Agente HTTPS configurado com ${caArray.length} CA(s) na cadeia.`);\\n  } else {\\n    console.warn('⚠️  Agente HTTPS sem CA chain — handshake pode falhar (HTTP 495).');\\n  }\\n\\n  return new https.Agent({\\n    key: keyPem,\\n    cert: certPem,\\n    ca: caArray,\\n    rejectUnauthorized: process.env.ADN_AMBIENTE === 'producao',\\n  });\\n}\", \"first_replaced_line\": 242, \"last_replaced_line\": 254, \"replace\": \"  if (caArray && caArray.length > 0) {\\n    console.log(`🔐 Agente HTTPS configurado com ${caArray.length} CA(s) na cadeia.`);\\n  } else {\\n    console.warn('⚠️  Agente HTTPS sem CA chain — handshake pode falhar (HTTP 495).');\\n  }\\n\\n  // ── AUDITORIA: rejectUnauthorized ─────────────────────\\n  // Em PRODUÇÃO: true (valida cadeia do servidor — segurança máxima)\\n  // Em HOMOLOGAÇÃO/DEV: false (permite testar sem barreira de cadeia de confiança)\\n  const ambiente = process.env.ADN_AMBIENTE || 'homologacao';\\n  const rejectUnauthorized = ambiente === 'producao';\\n  console.log(\\n    `🔐 AUDITORIA AGENTE HTTPS: ambiente=\\\"${ambiente}\\\" | ` +\\n      `rejectUnauthorized=${rejectUnauthorized} ` +\\n      `${rejectUnauthorized ? '(modo SEGURO — valida cadeia)' : '(modo TESTE — ignora cadeia)'}`\\n  );\\n\\n  return new https.Agent({\\n    key: keyPem,\\n    cert: certPem,\\n    ca: caArray,\\n    rejectUnauthorized,\\n  });\\n}\"}">

Agora vou verificar o resultado final e te mandar o código completo:

Pronto! Aqui está o **código completo e atualizado** de `nfse-server/src/services/adnService.ts` com todas as 5 auditorias solicitadas. Cole no GitHub e faça commit:

```typescript
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
 */
function pfxParaPem(pfxBuffer: Buffer, senha: string): PemMaterial {
  // ── AUDITORIA: Debug da senha (sem expor o valor) ────────
  const senhaLen = senha?.length ?? 0;
  console.log(
    `🔑 AUDITORIA SENHA: SENHA_CERT_PFX presente? ${senhaLen > 0 ? 'Sim' : 'NÃO'} | ` +
      `Caracteres: ${senhaLen} | ` +
      `Tipo: ${typeof senha}`
  );
  if (senhaLen === 0) {
    console.warn(
      '⚠️  SENHA VAZIA detectada — node-forge tentará abrir o PFX sem senha. ' +
        'Confirme que SENHA_CERT_PFX está configurada corretamente no Railway.'
    );
  }

  const pfxBinary = pfxBuffer.toString('binary');

  let p12Asn1: forge.asn1.Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(pfxBinary);
    console.log(`✅ PFX decodificado em ASN.1 com sucesso (${pfxBuffer.length} bytes).`);
  } catch (errAsn1: unknown) {
    const msg = errAsn1 instanceof Error ? errAsn1.message : String(errAsn1);
    console.error(`❌ FALHA ASN.1: o arquivo PFX parece corrompido ou não é DER válido. Detalhe: ${msg}`);
    throw new Error(`PFX corrompido ou formato inválido: ${msg}`);
  }

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
    console.log('✅ PFX aberto com sucesso usando SENHA_CERT_PFX.');
  } catch (e1: unknown) {
    const msg1 = e1 instanceof Error ? e1.message : String(e1);
    console.error(`⚠️  Tentativa 1 (com senha de ${senhaLen} chars) FALHOU: "${msg1}"`);

    try {
      p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, '');
      console.log('✅ PFX aberto com SENHA VAZIA (a senha configurada estava errada).');
    } catch (e2: unknown) {
      const msg2 = e2 instanceof Error ? e2.message : String(e2);
      console.error(`❌ Tentativa 2 (senha vazia) também FALHOU: "${msg2}"`);
      console.error(
        '🚨 DIAGNÓSTICO: A senha do certificado está incorreta OU o arquivo PFX está corrompido.\n' +
          '   • Verifique SENHA_CERT_PFX no Railway (cuidado com espaços e quebras de linha)\n' +
          '   • Reexporte o PFX do certificado original e atualize CERT_PFX_BASE64'
      );
      throw new Error(
        `Falha ao abrir o PFX (mac verify failure). Senha incorreta ou arquivo corrompido. Detalhe: ${msg1}`
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

  const allCerts = certBags.filter((b) => b.cert).map((b) => b.cert!);

  console.log(`🔗 ═══ CADEIA DE CERTIFICADOS DO PFX (${allCerts.length} cert) ═══`);

  allCerts.forEach((cert, idx) => {
    const cn = cert.subject.getField('CN')?.value || 'sem CN';
    const o = cert.subject.getField('O')?.value || 'sem O';
    const ou = cert.subject.getField('OU')?.value || 'sem OU';
    const issuerCn = cert.issuer.getField('CN')?.value || 'sem issuer';
    const issuerO = cert.issuer.getField('O')?.value || 'sem issuer-O';
    const isSelfSigned = cn === issuerCn;
    const validFrom = cert.validity.notBefore.toISOString().substring(0, 10);
    const validTo = cert.validity.notAfter.toISOString().substring(0, 10);
    const serial = cert.serialNumber?.substring(0, 16) || 'sem serial';
    const expirado = cert.validity.notAfter < new Date();

    console.log(`   ┌─ [${idx}] ${isSelfSigned ? '🔒 ROOT (self-signed)' : '📄 CERT'}`);
    console.log(`   │  Subject CN : "${cn}"`);
    console.log(`   │  Subject O  : "${o}" | OU: "${ou}"`);
    console.log(`   │  Issuer  CN : "${issuerCn}"`);
    console.log(`   │  Issuer  O  : "${issuerO}"`);
    console.log(`   │  Validade   : ${validFrom} → ${validTo}${expirado ? ' ⚠️  EXPIRADO!' : ' ✅'}`);
    console.log(`   └─ Serial    : ${serial}...`);
  });
  console.log(`🔗 ═══════════════════════════════════════════════════════`);

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

  if (chainPresente) {
    try {
      const cleanedBase64 = rawChainEnv!.trim().replace(/[\r\n\s]/g, '');
      const chainBuffer = Buffer.from(cleanedBase64, 'base64');
      const chainPemFromEnv = chainBuffer.toString('utf-8');
      const matches = chainPemFromEnv.match(/-----BEGIN CERTIFICATE-----/g);
      const count = matches?.length || 0;

      if (count === 0) {
        console.error('❌ CERT_CHAIN_BASE64 decodificada mas não contém certificados PEM válidos.');
      } else {
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

function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH;
  const pfxPassword = process.env.SENHA_CERT_PFX || process.env.CERT_PFX_PASSWORD || '';

  let pfxBuffer: Buffer;

  if (process.env.CERT_PFX_BASE64) {
    pfxBuffer = Buffer.from(process.env.CERT_PFX_BASE64, 'base64');
    console.log(`🔐 AUDITORIA: Certificado via CERT_PFX_BASE64 → ${pfxBuffer.length} bytes`);
    if (pfxBuffer.length < 1000) {
      console.warn(`⚠️  PFX muito pequeno (${pfxBuffer.length} bytes) — provavelmente truncado/corrompido!`);
    }
  } else {
    if (!pfxPath) {
      throw new Error('Variável CERT_PFX_PATH não definida.');
    }

    // ── AUDITORIA: Verificação completa do arquivo ────────
    console.log(`🔍 AUDITORIA ARQUIVO: Verificando "${pfxPath}"...`);
    if (!fs.existsSync(pfxPath)) {
      console.error(`❌ AUDITORIA: Arquivo NÃO EXISTE em "${pfxPath}"`);
      console.error(`   CWD atual: ${process.cwd()}`);
      try {
        const certsDir = pfxPath.substring(0, pfxPath.lastIndexOf('/')) || './certs';
        if (fs.existsSync(certsDir)) {
          const files = fs.readdirSync(certsDir);
          console.error(`   Conteúdo de "${certsDir}": [${files.join(', ')}]`);
        } else {
          console.error(`   Diretório "${certsDir}" também não existe.`);
        }
      } catch (e) {
        console.error(`   Não foi possível listar o diretório.`);
      }
      throw new Error(`Certificado não encontrado em: ${pfxPath}`);
    }

    const stats = fs.statSync(pfxPath);
    console.log(
      `✅ AUDITORIA: Arquivo encontrado | Tamanho: ${stats.size} bytes | ` +
        `Modificado: ${stats.mtime.toISOString()} | ` +
        `Permissões: ${(stats.mode & 0o777).toString(8)}`
    );
    if (stats.size < 1000) {
      console.warn(`⚠️  PFX muito pequeno (${stats.size} bytes) — provavelmente corrompido!`);
    }
    if (stats.size > 50000) {
      console.warn(`⚠️  PFX muito grande (${stats.size} bytes) — verifique se não é o arquivo errado.`);
    }

    pfxBuffer = fs.readFileSync(pfxPath);
    console.log(`🔐 Certificado carregado do disco: ${pfxPath} (${pfxBuffer.length} bytes lidos)`);

    if (pfxBuffer[0] !== 0x30) {
      console.warn(
        `⚠️  Primeiro byte = 0x${pfxBuffer[0].toString(16)} (esperado 0x30). ` +
          'O arquivo pode não ser um PFX/DER válido — talvez esteja em base64?'
      );
    }
  }

  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

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

  // ── AUDITORIA: rejectUnauthorized ─────────────────────
  const ambiente = process.env.ADN_AMBIENTE || 'homologacao';
  const rejectUnauthorized = ambiente === 'producao';
  console.log(
    `🔐 AUDITORIA AGENTE HTTPS: ambiente="${ambiente}" | ` +
      `rejectUnauthorized=${rejectUnauthorized} ` +
      `${rejectUnauthorized ? '(modo SEGURO — valida cadeia)' : '(modo TESTE — ignora cadeia)'}`
  );

  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized,
  });
}

export const emitirNotaNacional = async (xmlString: string): Promise => {
  try {
    const bufferXml = Buffer.from(xmlString, 'utf-8');
    const gzippedBuffer = await gzip(bufferXml);
    console.log(`📦 XML compactado: ${bufferXml.length} bytes → GZIP ${gzippedBuffer.length} bytes`);

    const xmlBase64Gzip = gzippedBuffer.toString('base64');

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

    const httpsAgent = criarAgenteMTLS();

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
```

### O que cada auditoria faz quando você redeployar:

1. **🔍 AUDITORIA ARQUIVO**: mostra tamanho exato em bytes via `fs.statSync`, data de modificação, permissões e o primeiro byte (deve ser `0x30` para PFX válido).
2. **🔑 AUDITORIA SENHA**: confirma se `SENHA_CERT_PFX` foi lida (sem expor o valor) e quantos caracteres tem.
3. **❌ Erro de descriptografia**: captura a mensagem exata do node-forge nas duas tentativas (com senha e com senha vazia) e dá um diagnóstico claro.
4. **🔗 CADEIA DETALHADA**: mostra Subject CN/O/OU, Issuer CN/O, validade e serial de cada cert — você verá se o cert é o correto e se a cadeia ICP-Brasil está presente.
5. **🔐 AUDITORIA AGENTE HTTPS**: confirma `rejectUnauthorized=false` em homologação para isolar se o problema é cadeia de confiança.

Apliquei as 5 auditorias profundas no `adnService.ts`. Cole no GitHub, redeploye no Railway e me mande os logs — com eles vamos identificar com precisão se o 495 vem de senha errada, PFX corrompido ou cadeia ICP-Brasil incompleta.
 
