import express from 'express';
import cors from 'cors';
import * as adnService from './services/adnService';

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
    
    // Usa a função de mapeamento direto que está exposta no adnService
    const resultado = await adnService.emitirNotaNacionalFromDados(req.body);
    return res.status(200).json(resultado);
  } catch (erro: any) {
    console.error('[RAILWAY ERR] Erro na emissão:', erro.message);
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

/**
 * 🔍 ROTA: Consulta de Protocolo
 */
app.get('/nfse/consultar/:protocolo', async (req, res) => {
  try {
    const { protocolo } = req.params;
    console.log(`[RAILWAY REQ] Consultando status do protocolo: ${protocolo}`);
    
    const resultado = await adnService.consultarProtocolo(protocolo);
    
    // Tratamento flexível usando "as any" para burlar a trava de tipo do TS no retorno da API
    const dadosResposta = resultado as any;

    if (dadosResposta.sucesso) {
      return res.status(200).json({
        sucesso: true,
        dados: {
          numeroNfse: dadosResposta.numeroNfse || (dadosResposta.dados ? dadosResposta.dados.numeroNfse : null),
          chaveAcesso: dadosResposta.chaveAcesso || (dadosResposta.dados ? dadosResposta.dados.chaveAcesso : null),
          xmlRetorno: dadosResposta.xmlRetorno || (dadosResposta.dados ? dadosResposta.dados.xmlRetorno : null),
          urlPdf: dadosResposta.urlPdf || (dadosResposta.dados ? dadosResposta.dados.urlPdf : null),
          urlXml: dadosResposta.urlXml || (dadosResposta.dados ? dadosResposta.dados.urlXml : null)
        }
      });
    }

    // Se ainda não foi processada (Fila 210)
    return res.status(200).json({
      sucesso: false,
      status: 'aguardando',
      mensagem: 'Nota ainda em processamento na fila do governo.',
      detalhes: dadosResposta.detalhes || dadosResposta.mensagem
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
