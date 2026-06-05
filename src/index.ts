import puppeteer from 'puppeteer';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || '';

// ID fixo do heartbeat que o Lovable está monitorando na interface
const HEARTBEAT_ID = '00000000-0000-0000-0000-000000000001';

/**
 * 📝 Envia os logs de execução direto para a tabela do Supabase
 */
async function registrarLog(level: 'INFO' | 'SUCESSO' | 'ERRO' | 'WARN', message: string, hotelId: string | null = null) {
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[RPA] [${timestamp}] [${level}] ${message}`);

  try {
    await axios.post(`${SUPABASE_URL}/rest/v1/robo_logs`, {
      level,
      message,
      hotel_id: hotelId
    }, {
      headers: { 
        'apikey': SUPABASE_ANON_KEY, 
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json'
      }
    });
  } catch (error: any) {
    console.error('[RPA ERR] Erro ao persistir log no Supabase:', error.message);
  }
}

/**
 * 💓 Atualiza a saúde do robô para o painel do Lovable não dar "Offline"
 */
async function enviarHeartbeat(status: 'rodando' | 'aguardando' | 'erro') {
  try {
    await axios.patch(`${SUPABASE_URL}/rest/v1/robo_heartbeat?id=eq.${HEARTBEAT_ID}`, {
      status_atual: status,
      ultima_atividade: new Date().toISOString(),
      memoria_uso: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
    }, {
      headers: { 
        'apikey': SUPABASE_ANON_KEY, 
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json'
      }
    });
  } catch (error: any) {
    console.error('[RPA ERR] Erro ao enviar Heartbeat:', error.message);
  }
}

/**
 * 📥 Busca comandos pendentes enviados pelo botão "Executar Agora" do painel
 */
async function verificarComandosPendentes() {
  try {
    const resposta = await axios.get(`${SUPABASE_URL}/rest/v1/robo_comandos?status=eq.pendente&limit=1`, {
      headers: { 
        'apikey': SUPABASE_ANON_KEY, 
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}` 
      }
    });
    return resposta.data[0] || null;
  } catch (error: any) {
    console.error('[RPA ERR] Erro ao buscar comandos na fila:', error.message);
    return null;
  }
}

/**
 * 🔄 Atualiza o status do comando na fila de processamento
 */
async function atualizarStatusComando(id: string, status: 'executando' | 'concluido' | 'falha') {
  try {
    await axios.patch(`${SUPABASE_URL}/rest/v1/robo_comandos?id=eq.${id}`, {
      status,
      executado_em: status !== 'executando' ? new Date().toISOString() : null
    }, {
      headers: { 
        'apikey': SUPABASE_ANON_KEY, 
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json'
      }
    });
  } catch (error: any) {
    console.error('[RPA ERR] Erro ao atualizar status do comando:', error.message);
  }
}

/* ==========================================================================
   CORE DA AUTOMAÇÃO (PUPPETEER RASPAGEM)
   ========================================================================== */

async function rodarFluxoScraping() {
  await enviarHeartbeat('rodando');
  await registrarLog('INFO', 'Iniciando ciclo de varredura nos bancos...');

  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--no-sandbox', 
      '--disable-setuid-sandbox', 
      '--disable-dev-shm-usage', 
      '--disable-gpu'
    ]
  });
  const page = await browser.newPage();

  try {
    await registrarLog('INFO', 'Navegador Puppeteer aberto com sucesso.');
    
    // 🏦 Aqui entrará a lógica de leitura da tabela `robo_bancos_config` 
    // e o preenchimento dos seletores nos sites dos bancos.
    
    await registrarLog('SUCESSO', 'Varredura de teste concluída. Painel conectado.');

  } catch (error: any) {
    await registrarLog('ERRO', `Falha crítica durante a raspagem: ${error.message}`);
    await enviarHeartbeat('erro');
  } finally {
    await browser.close();
    await registrarLog('INFO', 'Navegador fechado. Aguardando próxima chamada.');
    await enviarHeartbeat('aguardando');
  }
}

/* ==========================================================================
   FUNÇÃO DE INICIALIZAÇÃO (EXPORTADA PARA O INDEX.TS)
   ========================================================================== */

export function iniciarRoboExtrator() {
  // 1. Loop do Heartbeat (Garante o sinal de vida a cada 30 segundos)
  setInterval(() => { 
    enviarHeartbeat('aguardando'); 
  }, 30000);

  // 2. Loop de Verificação da Fila (Checa se você clicou em "Executar Agora" a cada 10 segundos)
  setInterval(async () => {
    const comando = await verificarComandosPendentes();
    if (comando) {
      await registrarLog('INFO', `Comando [${comando.tipo}] detectado! Iniciando execução forçada...`);
      await atualizarStatusComando(comando.id, 'executando');
      try {
        await rodarFluxoScraping();
        await atualizarStatusComando(comando.id, 'concluido');
      } catch {
        await atualizarStatusComando(comando.id, 'falha');
      }
    }
  }, 10000);

  // 3. Loop de Rotina Automática (Roda sozinho a cada 60 segundos)
  setInterval(async () => { 
    await rodarFluxoScraping(); 
  }, 60000);

  // Inicialização imediata assim que o servidor Express liga
  registrarLog('INFO', 'Módulo do Robô Extrator acoplado e ativo em segundo plano.');
  enviarHeartbeat('aguardando');
}
