/**
 * Cria o agente HTTPS fundindo os certificados do PFX com o bundle ICP-Brasil do disco.
 */
function criarAgenteMTLS(): https.Agent {
  const pfxPath = process.env.CERT_PFX_PATH || './certs/certificado.pfx';
  const pfxPassword = process.env.SENHA_CERT_PFX || '';
  const pfxBuffer = process.env.CERT_PFX_BASE64 
    ? Buffer.from(process.env.CERT_PFX_BASE64, 'base64') 
    : fs.readFileSync(pfxPath);

  // 1. Pegamos o material original do seu PFX (Chave e Certificado Cliente)
  const { keyPem, certPem, caPem } = pfxParaPem(pfxBuffer, pfxPassword);

  const caArray: string[] = [];

  // 2. FUSÃO: Lemos o bundle externo que baixamos do governo
  const bundlePath = '/app/certs/icp-brasil/icp-bundle.pem';
  try {
    if (fs.existsSync(bundlePath)) {
      const bundleContent = fs.readFileSync(bundlePath, 'utf-8');
      const bundleCerts = bundleContent.split(/(?=-----BEGIN CERTIFICATE-----)/g)
        .map(s => s.trim())
        .filter(s => s.length > 0);
      
      caArray.push(...bundleCerts);
      console.log(`🛡️ FUSÃO: ${bundleCerts.length} certificados do governo adicionados.`);
    }
  } catch (err: any) {
    console.error('⚠️ Erro ao fundir bundle externo:', err.message);
  }

  // 3. FUSÃO: Adicionamos a cadeia que já veio dentro do seu PFX
  if (caPem) {
    const fromPfx = caPem.split(/(?=-----BEGIN CERTIFICATE-----)/g)
      .map(s => s.trim())
      .filter(s => s.length > 0);
    caArray.push(...fromPfx);
  }

  // 4. Adicionamos o seu próprio certificado cliente na lista de confiança
  if (certPem) caArray.push(certPem.trim());

  console.log(`🔐 AGENTE HTTPS FINAL: ${caArray.length} certificados no total (PFX + Bundle).`);

  return new https.Agent({
    key: keyPem,
    cert: certPem,
    ca: caArray,
    rejectUnauthorized: true, // Agora ele tem tudo para validar!
  });
}
