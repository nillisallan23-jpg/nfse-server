import dotenv from 'dotenv';
import express, { Request, Response, RequestHandler } from 'express';
// Importamos todas as funções necessárias do serviço (incluindo o consultarProtocolo)
import { 
  emitirNotaNacional, 
  emitirNotaNacionalFromDados, 
  consultarProtocolo 
} from './services/adnService';

// Carrega as variáveis do ambiente
dotenv.config();

const app = express();

// Aumentamos o limite para garantir o recebimento de payloads maiores
app.use(express.json({ limit: '15mb' }));

/**
 * 🩺 ROTA DE SAÚDE (HEALTH CHECK)
 */
app.get('/health', (_req: Request, res: Response) => {
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
app.get('/', (_req: Request, res: Response) => {
  res.send('🚀 Servidor de Emissão NFS-e Nacional (NFSe-Server) operando!');
});

/**
 * 📄 POST /nfse/emitir
 * Rota inteligente: identifica se você enviou XML ou JSON e processa adequadamente.
 */
const emitirHandler: RequestHandler = async (req, res) => {
  try {
    const payload = req.body;

    if (!payload || Object.keys(payload).length === 0) {
      res.status(400).json({
        sucesso: false,
        mensagem: 'Requisição vazia.'
      });
      return;
    }

    let resultado;

    // 1. Se enviou uma string de XML (formato antigo ou direto)
    if (payload.xml && typeof payload.xml === 'string') {
      console.log(`\n[${new Date().toISOString()}] 📨 Recebido XML para envio direto.`);
      resultado = await emitirNotaNacional(payload.xml);
    } 
    // 2. Se enviou o objeto estruturado (dadosDPS)
    else if (payload.dadosDPS) {
      console.log(`\n[${new Date().toISOString()}] 📥 Recebido objeto dadosDPS. Iniciando fluxo.`);
      resultado = await emitirNotaNacionalFromDados(payload.dadosDPS);
    }
    // 3. Caso o JSON tenha sido enviado sem "embrulho", tenta processar o payload inteiro
    else {
      console.log(`\n[${new Date().toISOString()}] 📥 Recebido JSON direto. Tentando processamento.`);
      resultado = await emitirNotaNacionalFromDados(payload);
    }

    if (resultado.sucesso) {
      console.log('✅ Processo finalizado com sucesso.');
      res.status(200).json(resultado);
      return;
    } else {
      console.error('⚠️ Falha na operação.');
      res.status(422).json(resultado);
      return;
    }

  } catch (error: any) {
    console.error('❌ Erro crítico no endpoint /emitir:', error?.message || error);
    res.status(500).json({
      sucesso: false,
      mensagem: 'Erro interno no servidor.',
      erro: error?.message || String(error)
    });
    return;
  }
};

app.post('/nfse/emitir', emitirHandler);

/**
 * 🔍 POST /nfse/consultar
 * Rota que o Lovable chama para verificar se a prefeitura liberou a nota do protocolo assíncrono.
 */
const consultarHandler: RequestHandler = async (req, res) => {
  try {
    const { protocolo } = req.body;

    if (!protocolo) {
      res.status(400).json({ 
        sucesso: false, 
        erro: 'Protocolo é obrigatório.' 
      });
      return;
    }

    console.log(`\n[${new Date().toISOString()}] 🔍 Consultando status do protocolo: ${protocolo}`);

    // Chama a função existente no adnService
    const resultado = await consultarProtocolo(protocolo);

    // Retorna a estrutura exata que o Lovable precisa interpretar
    res.json({
      sucesso: true,
      dados: {
        numeroNfse: resultado.numeroNfse || null,
        chaveAcesso: resultado.chaveAcesso || null,
        xmlRetorno: resultado.xmlRetorno || null,
        urlPdf: resultado.urlPdf || null,
        urlXml: resultado.urlXml || null
      }
    });
    return;

  } catch (error: any) {
    console.error('❌ Erro ao consultar protocolo:', error?.message || error);
    res.status(500).json({ 
      sucesso: false, 
      erro: error?.message || String(error) 
    });
    return;
  }
};

app.post('/nfse/consultar', consultarHandler);

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`\n==============================================`);
  console.log(`🚀 SERVIDOR NFSE-SERVER ATIVO`);
  console.log(`📡 PORTA: ${PORT}`);
  console.log(`🔗 REPOSITÓRIO: nillisallan23-jpg/nfse-server`);
  console.log(`==============================================\n`);
});
