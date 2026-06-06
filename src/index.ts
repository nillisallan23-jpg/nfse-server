

import express from 'express';

import * as adnService from './services/adnService';



const app = express();



/**

 * 🔒 CONFIGURAÇÃO DE CORS

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

 * 🛡️ MIDDLEWARE NATIVO ANTI-ERRO 415 E 404

 * Configura o Express para aceitar qualquer XML vindo do Supabase como string pura no req.body

 */

app.use('/nfse/emitir', express.text({ type: ['application/xml', 'text/xml', '*/*'], limit: '10mb' }));



// Fallbacks de decodificação normais para as demais rotas (como a de consulta)

app.use(express.json({ limit: '10mb' })); 

app.use(express.urlencoded({ extended: true, limit: '10mb' }));



/**

 * 💓 ROTA DE MONITORAMENTO (HEALTH CHECK)

 */

app.get('/health', (req, res) => {

  res.status(200).json({ status: 'online' });

});



/**

 * 🚀 ROTA PRINCIPAL: RECEBE O XML, EFETUA A ASSINATURA E TRANSMITE

 */

app.post('/nfse/emitir', async (req, res) => {

  try {

    console.log('[RAILWAY] Nova requisição de emissão recebida com sucesso.');



    if (!req.body || typeof req.body !== 'string' || req.body.trim().length === 0) {

      console.error('[RAILWAY ERR] O corpo da requisição veio vazio ou não é uma string XML.');

      return res.status(400).json({ sucesso: false, mensagem: 'Payload XML inválido ou vazio.' });

    }



    // Passa a string limpa para o adnService

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

    return res.status(500).json({ sucesso: false, message: erro.message });

  }

});



const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {

  console.log(`🚀 SERVIDOR NFSE-SERVER ATIVO E ASSINANDO NA PORTA ${PORT}`);

});
