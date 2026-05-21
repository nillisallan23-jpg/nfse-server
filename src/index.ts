import express from 'express';
import * as adnService from './services/adnService';

const app = express();

/**
 * 🛡️ MIDDLEWARE AVANÇADO DE CAPTURA BRUTA (ANTI-ERRO 415 NA ENTRADA)
 * Intercepta os streams de dados puros do Supabase antes que o body-parser automático
 * do Express avalie os cabeçalhos de Content-Type e cause uma rejeição de mídia.
 */
app.use((req, res, next) => {
  if (req.url === '/nfse/emitir' && req.method === 'POST') {
    const chunks: Buffer[] = [];
    
    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });
    
    req.on('end', () => {
      const bufferCompleto = Buffer.concat(chunks);
      // Converte o payload interceptado em string UTF-8 limpa
      req.body = bufferCompleto.toString('utf8'); 
      next();
    });

    req.on('error', (err) => {
      console.error('[RAILWAY STRM ERR] Erro ao ler stream da requisição:', err.message);
      res.status(400).json({ sucesso: false, mensagem: 'Erro na leitura dos dados brutos.' });
    });
  } else {
    next();
  }
});

// Fallbacks de decodificação normais para as demais rotas do servidor
app.use(express.json({ limit: '10mb' })); 
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * 🔒 CONFIGURAÇÃO DE CORS PROFISSIONAL
 */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

/**
 * 💓 ROTA DE MONITORAMENTO (HEALTH CHECK)
 */
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online' });
});

/**
 * 🚀 ROTA PRINCIPAL: RECEBE O XML INTERCEPTADO, EFETUA A ASSINATURA E TRANSMITE
 */
app.post('/nfse/emitir', async (req, res) => {
  try {
    console.log('[RAILWAY] Nova requisição de emissão recebida com sucesso.');

    // O adnService agora receberá a string limpa injetada de forma isolada pelo stream middleware
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
