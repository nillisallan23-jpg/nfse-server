import express from 'express';
import * as adnService from './services/adnService';

const app = express();

// Configuração de interpretadores de requisição (Middlewares)
app.use(express.json()); // Lê JSON normalmente
app.use(express.text({ type: ['application/xml', 'text/xml'], limit: '10mb' })); // CRUCIAL: Lê XML puro do Lovable como string

// Middleware manual simples para habilitar CORS sem precisar do pacote externo
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

    // 1. Caso o Lovable envie o XML puro diretamente no corpo como String
    if (typeof req.body === 'string' && req.body.includes('<?xml')) {
      console.log('[RAILWAY] Identificado envio de XML puro via texto. Processando e assinando...');
      const resultado = await adnService.emitirNotaNacional(req.body);
      return res.status(200).json(resultado);
    }

    // 2. Fallback caso envie envelopado em JSON { xmlString: "..." }
    if (req.body && req.body.xmlString) {
      console.log('[RAILWAY] Processando propriedade xmlString recebida dentro do JSON...');
      const resultado = await adnService.emitirNotaNacional(req.body.xmlString);
      return res.status(200).json(resultado);
    }

    // 3. Fallback caso o Supabase mande o formato antigo de dados estruturados dadosDPS
    if (req.body && req.body.dadosDPS) {
      console.log('[RAILWAY] Processando via formato estruturado dadosDPS (Com Assinatura Digital A1).');
      const resultado = await (adnService as any).emitirNotaNacionalFromDados(req.body.dadosDPS);
      return res.status(200).json(resultado);
    } 
    
    // 4. Fallback caso mande a propriedade antiga .xml
    if (req.body && req.body.xml) {
      console.log('[RAILWAY] Alerta: Recebido formato legado (propriedade .xml).');
      const resultado = await adnService.emitirNotaNacional(req.body.xml);
      return res.status(200).json(resultado);
    }

    // 5. Se mandar o objeto direto sem a propriedade envelopada dadosDPS
    console.log('[RAILWAY] Processando objeto direto como fallback.');
    const resultado = await (adnService as any).emitirNotaNacionalFromDados(req.body);
    return res.status(200).json(resultado);

  } catch (erro: any) {
    console.error('[RAILWAY ERR] Erro crítico na rota /nfse/emitir:', erro.message);
    return res.status(500).json({ sucesso: false, mensagem: erro.message });
  }
});

/**
 * 🔍 ROTA DE CONSULTA: Blindada contra erros de compilação
 */
app.get('/nfse/consultar/:protocolo', async (req, res) => {
  try {
    const { protocolo } = req.params;
    console.log(`[RAILWAY] Consultando protocolo: ${protocolo}`);
    
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
