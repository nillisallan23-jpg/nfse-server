import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
// Importamos as duas funções: uma para XML direto e outra para o JSON (DadosDPS)
import { emitirNotaNacional, emitirNotaNacionalFromDados } from './services/adnService';

// Carrega as variáveis do ambiente
dotenv.config();

const app = express();

// Aumentamos o limite para garantir o recebimento de payloads maiores
app.use(express.json({ limit: '15mb' }));

/**
 * 🩺 ROTA DE SAÚDE (HEALTH CHECK)
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    modelo: 'ADN Nacional (Serpro)',
    ambiente: process.env.ADN_AMBIENTE === 'producao' ? 'Produção' : 'Homologação/Restrita',
    repositorio: 'nfse-server',
    timestamp: new Date().toISOString()
  });
});

/**
 * 🏠 ROTA RAIZ
 */
app.get('/', (req: Request, res: Response) => {
  res.send('🚀 Servidor de Emissão NFS-e Nacional (NFSe-Server) operando!');
});

/**
 * 📄 POST /nfse/emitir
 * Rota inteligente: identifica se você enviou XML ou JSON e processa adequadamente.
 */
app.post('/nfse/emitir', async (req: Request, res: Response) => {
  try {
    const payload = req.body;

    if (!payload || Object.keys(payload).length === 0) {
      return res.status(400).json({
        sucesso: false,
        mensagem: 'Requisição vazia.'
      });
    }

    let resultado;

    // Lógica de Decisão:
    if (payload.xml && typeof payload.xml === 'string') {
      // Se enviou { "xml": "<xml>..." }
      console.log(`\n[${new Date().toISOString()}] 📨 Recebido XML para envio direto.`);
      resultado = await emitirNotaNacional(payload.xml);
    } else {
      // Se enviou o JSON completo (DadosDPS)
      console.log(`\n[${new Date().toISOString()}] 📥 Recebido JSON. Iniciando fluxo de assinatura automática.`);
      resultado = await emitirNotaNacionalFromDados(payload);
    }

    if (resultado.sucesso) {
      console.log('✅ Processo finalizado com sucesso.');
      return res.status(200).json(resultado);
    } else {
      console.error('⚠️ Falha na operação.');
      return res.status(422).json(resultado);
    }

  } catch (error: any) {
    console.error('❌ Erro crítico no endpoint /emitir:', error.message);
    return res.status(500).json({
      sucesso: false,
      mensagem: 'Erro interno no servidor.',
      erro: error.message
    });
  }
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`🚀 SERVIDOR NFSE-SERVER ATIVO`);
  console.log(`📡 PORTA: ${PORT}`);
  console.log(`🔗 REPOSITÓRIO: nillisallan23-jpg/nfse-server`);
  console.log(`==============================================\n`);
});
