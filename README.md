# Servidor de Emissão NFS-e (Padrão Nacional ADN)

Este servidor automatiza a emissão de Notas Fiscais de Serviço eletrônicas seguindo o novo **Padrão Nacional ADN**, integrando com a API do Governo via mTLS e compressão GZip.

## 🚀 Tecnologias
- Node.js & TypeScript
- Express (API HTTP)
- mTLS (Autenticação via Certificado Digital A1)
- GZip (Compactação obrigatória do padrão ADN)

## ⚙️ Configuração (Variáveis de Ambiente no Railway)

Para o servidor funcionar, as seguintes variáveis devem estar configuradas:

| Variável | Descrição |
|----------|-----------|
| `ADN_CNPJ_CONCESSIONARIA` | CNPJ do Hotel (apenas números) |
| `SENHA_CERT_PFX` | Senha do certificado digital .pfx |
| `CERT_PFX_PATH` | Nome do arquivo do certificado (ex: `certificado.pfx`) |
| `PORT` | Porta do servidor (padrão: `8080`) |

## 🛠️ Instalação e Execução

```bash
# Instalar dependências
npm install

# Rodar em modo desenvolvimento
npm run dev

# Compilar e Rodar em Produção (Railway)
npm run build
npm start