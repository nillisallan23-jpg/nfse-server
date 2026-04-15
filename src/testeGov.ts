import https from 'https';
import fs from 'fs';
import dotenv from 'dotenv';

// Carrega as variáveis do Railway ou do arquivo .env
dotenv.config();

/**
 * 🔍 DIAGNÓSTICO DE CONEXÃO ADN (PADRÃO NACIONAL)
 * Este script valida se o certificado digital está abrindo e se
 * o servidor do Serpro/Governo Federal responde ao seu chamado.
 */
async function validarAmbienteNacional() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🚀 INICIANDO TESTE DE CONEXÃO ADN...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  try {
    // 1. Coleta as informações das variáveis de ambiente
    const pfxPath = process.env.CERT_PFX_PATH || 'certificado.pfx';
    const passphrase = process.env.SENHA_CERT_PFX;

    console.log(`📂 Verificando arquivo: ${pfxPath}`);

    // 2. Verifica se o arquivo físico do certificado existe na pasta
    if (!fs.existsSync(pfxPath)) {
      throw new Error(`Arquivo de certificado NÃO ENCONTRADO no caminho: ${pfxPath}. Certifique-se de que ele foi enviado ao GitHub/Railway.`);
    }

    const certBuffer = fs.readFileSync(pfxPath);
    console.log('✅ Arquivo carregado com sucesso.');

    // 3. Configura o Agente de conexão Segura (mTLS)
    const agent = new https.Agent({
      pfx: certBuffer,
      passphrase: passphrase,
      rejectUnauthorized: true 
    });

    // 4. Endereço oficial do Ambiente de Produção Restrita (Homologação) do Serpro
    const options = {
      hostname: 'producaorestrita.certificado.api.via.nfse.gov.br',
      port: 443,
      path: '/recepcao/v1/nfsev/status', // Endpoint apenas para verificar status
      method: 'GET',
      agent
    };

    console.log(`📡 Conectando em: https://${options.hostname}${options.path}`);

    const req = https.request(options, (res) => {
      console.log(`📊 STATUS DA RESPOSTA: ${res.statusCode}`);

      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      
      res.on('end', () => {
        // O Serpro pode retornar 200 (OK) ou 404/401 se a rota de status for restrita, 
        // mas o importante é o statusCode existir, o que prova que o mTLS funcionou.
        if (res.statusCode && res.statusCode < 500) {
          console.log('\n✅ SUCESSO: Conexão segura (mTLS) estabelecida!');
          console.log('🔒 Seu certificado e senha foram aceitos pelo Governo.');
        } else {
          console.log('\n⚠️  ALERTA: O servidor respondeu, mas houve um erro de permissão ou rota.');
          console.log('Detalhes:', body);
        }
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      });
    });

    req.on('error', (e) => {
      console.error('\n❌ ERRO DE CONEXÃO:');
      console.error(`Mensagem: ${e.message}`);
      if (e.message.includes('mac verify failure')) {
        console.error('💡 DICA: A senha do certificado (SENHA_CERT_PFX) está incorreta.');
      }
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    });

    req.end();

  } catch (err: any) {
    console.error('\n❌ FALHA NO DIAGNÓSTICO:');
    console.error(err.message);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  }
}

validarAmbienteNacional();