import express from 'express';
import cors from 'cors';
import { emitirNotaNacionalFromDados, consultarProtocolo } from './services/adnService';

const app = express();
app.use(cors());
app.use(express.json());

// Rota de Saúde do Servidor
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online', ambiente: process.env.NFSE_AMBIENTE || 'producao' });
});

/**
 * 🚀 ROTA: Emissão de Nota
 */
app.post('/nfse/emitir', async (req, res) => {
  try {
    console.log('[RAILWAY REQ] Nova requisição de emissão recebida.');
    const resultado = await emitirNotaNacionalFromDados(req.body);
    return res.status(200).json(resultado);
  } catch (erro: any) {
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

/**
 * 🔍 ROTA: Consulta de Protocolo (A que o seu painel precisa!)
 */
app.get('/nfse/consultar/:protocolo', async (req, res) => {
  try {
    const { protocolo } = req.params;
    console.log(`[RAILWAY REQ] Consultando status do protocolo: ${protocolo}`);
    
    const resultado = await consultarProtocolo(protocolo);
    
    // Se o governo retornar sucesso, devolvemos a estrutura completa mapeada
    if (resultado.sucesso) {
      return res.status(200).json({
        sucesso: true,
        dados: {
          numeroNfse: resultado.numeroNfse,
          chaveAcesso: resultado.chaveAcesso,
          xmlRetorno: resultado.xmlRetorno,
          urlPdf: resultado.urlPdf,
          urlXml: resultado.urlXml
        }
      });
    }

    // Se der erro ou ainda estiver processando na fila (210), responde em modo aguardando
    return res.status(200).json({
      sucesso: false,
      status: 'aguardando',
      mensagem: 'Nota ainda em processamento na fila do governo.',
      detalhes: resultado.detalhes
    });

  } catch (erro: any) {
    console.error('[RAILWAY ERR] Erro na rota de consulta:', erro.message);
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 Servidor fiscal rodando perfeitamente na porta ${PORT}`);
});
