# BlueSales Platform — produção

## Stack
- Node.js + Express
- PostgreSQL
- Express Session + `connect-pg-simple`
- bcrypt para senhas
- Helmet
- Rate limiting
- Zod para validação
- Nodemailer para recuperação de senha
- Docker / Docker Compose

## Rodar localmente com Docker

1. Instale Docker.
2. Copie `.env.example` se desejar customizar.
3. Edite `docker-compose.yml` e altere as senhas/secrets.
4. Execute:

```bash
docker compose up --build
```

5. Abra `http://localhost:3000`.

Usuário inicial:
`admin@bluesales.local`

Senha inicial:
`Admin@123`

Troque imediatamente.

## Banco

O PostgreSQL possui:
- users
- products
- customers
- sales
- password_resets
- user_sessions (criada pelo connect-pg-simple)

Para um banco existente:

```bash
psql "$DATABASE_URL" -f schema.sql
node scripts/seed.js
```

## Funcionalidades de produção

### Autenticação
- Login real.
- Sessões no PostgreSQL.
- Cookies HttpOnly/SameSite.
- HTTPS via `secure=true` em produção.
- Logout.
- Rate limit no login.
- Recuperação de senha por token de uso único e expiração.
- Senhas com bcrypt.

### RBAC
`ADMIN`:
- gerencia usuários;
- altera roles;
- ativa/desativa contas;
- altera própria senha/perfil;
- acessa endpoints administrativos.

`USER`:
- acesso somente às APIs permitidas;
- não consegue elevar a própria role;
- recebe HTTP 403 ao tentar rotas administrativas.

### CRUD
- Produtos: listar, criar, editar, desativar.
- Clientes: listar, criar, editar, desativar.
- Vendas: listar e registrar.
- Dashboard: métricas calculadas diretamente do PostgreSQL.

## Deploy

Pode ser publicado em qualquer infraestrutura que rode Node + PostgreSQL.

Checklist:
- [ ] `NODE_ENV=production`
- [ ] `SESSION_SECRET` aleatório e forte
- [ ] `DATABASE_URL` seguro
- [ ] HTTPS
- [ ] senha inicial alterada
- [ ] SMTP configurado
- [ ] backups do PostgreSQL
- [ ] monitoramento/logs
- [ ] domínio apontado para o servidor
- [ ] política de privacidade/termos adequada ao negócio

## Segurança

O frontend nunca é considerado autoridade para permissões. Toda rota administrativa usa middleware `role("ADMIN")` no servidor.

Antes de comercializar a plataforma, recomendo adicionar auditoria de ações administrativas, MFA para administradores, CSRF dependendo da estratégia de autenticação, monitoramento e backups automatizados.
