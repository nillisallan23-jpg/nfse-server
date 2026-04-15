import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import { emitirNotaNacional } from './services/adnService';

// Carrega as variáveis do arquivo .env (local) ou do Railway
dotenv.config();

const app = express();

// Aumentamos o limite para 10mb para garantir que XMLs grandes não sejam bloqueados
app.use(express.json({ limit: '10mb' }));

/**
 * 🩺 ROTA DE SAÚDE (HEALTH CHECK)
 * Serve para verificar se o servidor está online e configurado.
 * Acesse: https://pix-check-instant-view-production.up.railway.app/health
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    modelo: 'ADN Nacional (Serpro)',
    ambiente: process.env.ADN_AMBIENTE === '2' ? 'Homologação/Restrita' : 'Produção',
    servico: 'pix-check-instant-view',
    timestamp: new Date().toISOString()
  });
});

/**
 * 🏠 ROTA RAIZ
 */
app.get('/', (req: Request, res: Response) => {
  res.send('🚀 Servidor de Emissão NFS-e Nacional ADN está operando!');
});

/**
 * 📄 POST /nfse/emitir
 * Recebe o XML do MeConferi e repassa para o adnService processar (Gzip + Base64).
 */
app.post('/nfse/emitir', async (req: Request, res: Response) => {
  try {
    const { xml } = req.body;

    // Validação básica do campo obrigatório
    if (!xml || typeof xml !== 'string') {
      return res.status(400).json({
        sucesso: false,
        mensagem: 'O campo "xml" é obrigatório e deve ser uma string.'
      });
    }

    console.log(`\n━━━ INÍCIO DO PROCESSAMENTO: ${new Date().toISOString()} ━━━`);
    console.log(`Tamanho do XML original: ${xml.length} caracteres.`);

    // Chama a função profissional de integração com o Serpro
    const resultado = await emitirNotaNacional(xml);

    if (resultado.sucesso) {
      console.log('✅ Emissão concluída com sucesso.');
      return res.status(200).json(resultado);
    } else {
      console.error('⚠️ Falha na emissão pela API Nacional.');
      return res.status(422).json(resultado);
    }

  } catch (error: any) {
    console.error('❌ Erro inesperado no servidor:', error.message);
    return res.status(500).json({
      sucesso: false,
      mensagem: 'Erro interno ao processar a nota fiscal.',
      erro: error.message
    });
  }
});

/**
 * 🚀 CONFIGURAÇÃO DA PORTA
 * O Railway injeta a porta correta na variável process.env.PORT.
 * Se não existir (local), usa a 8080.
 */
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`🚀 SERVIDOR RODANDO NA PORTA: ${PORT}`);
  console.log(`🩺 HEALTH CHECK: http://localhost:${PORT}/health`);
  console.log(`📄 EMISSÃO: http://localhost:${PORT}/nfse/emitir`);
  console.log(`==============================================\n`);
});