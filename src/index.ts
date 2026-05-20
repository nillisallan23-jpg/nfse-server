import express from 'express';
import * as adnService from './services/adnService';

const app = express();

// CORREÇÃO: Invertemos a ordem e adicionamos um fallback para capturar texto/xml de forma segura
app.use(express.text({ type: ['application/xml', 'text/xml', 'text/plain'], limit: '10mb' })); 
app.use(express.json({ limit: '10mb' })); 

// Middleware manual para habilitar CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online' });
});

/**
 * 🚀 ROTA PRINCIPAL: RECEBE XML PURO OU DADOS, ASSINA E ENVIA
 */
app.post('/nfse/emitir', async (req, res) => {
  try {
    console.log('[RAILWAY] Nova requisição de emissão recebida.');

    // CORREÇÃO: Simplificado. Como o adnService já trata se o payload é string, 
    // objeto, xmlString ou body, passamos o req.body direto de forma limpa.
    const resultado = await adnService.emitirNotaNacional(req.body);
    
    return res.status(200).json(resultado);

  } catch (erro: any) {
    console.error('[RAILWAY ERR] Erro crítico na rota /nfse/emitir:', erro.message);
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

/**
 * 🔍 ROTA DE CONSULTA
 */
app.get('/nfse/consultar/:protocolo', async (req, res) => {
  try {
    const { protocolo } = req.params;
    console.log(`[RAILWAY] Consultando protocolo: ${protocolo}`);
    
    // ALERTA: Certifique-se de implementar e exportar esta função dentro do seu './services/adnService'
    if (typeof (adnService as any).consultarProtocolo !== 'function') {
      throw new Error("A função 'consultarProtocolo' ainda não foi implementada no adnService.");
    }

    const resultado = await (adnService as any).consultarProtocolo(protocolo);
    const respostaComoAny = resultado as any;

    if (respostaComoAny && (respostaComoAny.sucesso || respostaComoAny.codigoRetorno === 200)) {
      return res.status(200).json({
        sucesso: true,
        dados: {
          numeroNfse: respostaComoAny.numeroNfse || (respostaComoAny.dados?.numeroNfse) || null,
          chaveAcesso: respostaComoAny.chaveAcesso || (respostaComoAny.dados?.chaveAcesso) || null,
          xmlRetorno: respostaComoAny.xmlRetorno || (respostaComoAny.dados?.xmlRetorno) || null,
          urlPdf: respostaComoAny.urlPdf || (respostaComoAny.dados?.urlPdf) || null,
          urlXml: respostaComoAny.urlXml || (respostaComoAny.dados?.urlXml) || null
        }
      });
    }

    return res.status(200).json({
      sucesso: false,
      status: 'aguardando',
      mensagem: 'Nota ainda em processamento na fila ou erro na resposta.',
      detalhes: respostaComoAny
    });

  } catch (erro: any) {
    console.error('[RAILWAY ERR] Erro na rota de consulta:', erro.message);
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 SERVIDOR NFSE-SERVER ATIVO E ASSINANDO NA PORTA ${PORT}`);
});
