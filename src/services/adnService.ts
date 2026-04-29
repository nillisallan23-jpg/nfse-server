/**
 * Cria o agente HTTPS injetando a cadeia completa na propriedade 'ca'.
 */
function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  const pfxBuffer = process.env.CERT_PFX_BASE64 
    ? Buffer.from(process.env.CERT_PFX_BASE64, 'base64') 
    : fs.readFileSync(pfxPath);

  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

  // Montagem do caArray para o Node.js
  const caArray: string[] = [];

  // 1. ADICIONADO: Forçar a leitura do arquivo icp-bundle.pem do disco
  const bundlePath = '/app/certs/icp-brasil/icp-bundle.pem';
  try {
    if (fs.existsSync(bundlePath)) {
      const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
      const bundleCerts = bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g).map(s => s.trim()).filter(s => s.length > 0);
      caArray.push(...bundleCerts);
      console.log(`🛡️ MANUAL: ${bundleCerts.length} certificados carregados do arquivo bundle.`);
    } else {
      console.warn('⚠️ ALERTA: Arquivo bundle não encontrado em:', bundlePath);
    }
  } catch (err: any) {
    console.error('❌ ERRO ao ler bundle manual:', err.message);
  }

  // 2. Mantém os certificados que já vinham do PFX
  if (caPem) {
    const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g).map(s => s.trim()).filter(s => s.length > 0);
    caArray.push(...fromPfx);
  }
  
  if (certPem) caArray.push(certPem.trim());

  console.log(`🔐 AGENTE HTTPS: Total de ${caArray.length} certificados injetados na CA.`);

  const ambiente = process.env.ADN_AMBIENTE || 'homologacao';
  
  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    // Em produção, rejectUnauthorized deve ser true para segurança máxima
    rejectUnauthorized: true, 
  });
}
