// server.js
require('dotenv').config();

// 1) Dependências
const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const expressLayouts = require('express-ejs-layouts');
const { uiMiddleware } = require('./src/middleware/ui');
const DB = require('./src/db');

// 2) App e Porta
const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const ADMIN_PASS = process.env.ADMIN_PASS || (!IS_PROD ? 'admin123' : null);

// Helper: assinatura ativa? (considera vitalício)
function isActive(user) {
  return (
    user &&
    (
      user.status === 'vitalicio' ||
      (user.status === 'active' &&
       user.access_expires_at &&
       new Date(user.access_expires_at) > new Date())
    )
  );
}

// ===== Helper de sessão única =====
function startUserSession(req, userId, remember = false) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => {
      if (err) return reject(err);

      const token = uuidv4();
      // grava no banco (derruba sessões antigas)
      DB.setUserSession(userId, token);

      // grava na sessão atual
      req.session.userId = userId;
      req.session.sessionToken = token;

      // lembrar de mim
      if (remember) {
        req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000; // 7 dias
      } else {
        req.session.cookie.expires = false;
        req.session.cookie.maxAge = null;
      }
      resolve();
    });
  });
}

// 3) Engine de views (EJS) e diretório das views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src'));

// 4) Arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// 5) Parsers e cookies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser(process.env.SESSION_SECRET || 'dev-secret'));

// 6) Segurança base
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));
app.use(compression());

// 7) Sessão (antes do CSRF)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  // name: 'sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD
  }
}));

// 8) Layouts + CSRF + UI (nessa ordem)
app.use(expressLayouts);

// CSRF por cookie (double-submit)
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD
  }
});
app.use(csrfProtection);

// Injeta brand/menu/csrfToken nas views
app.use(uiMiddleware);

// (2) Timeout por inatividade + expiração absoluta
const IDLE_MS = 30 * 60 * 1000;       // 30 minutos
const ABS_MS  = 24 * 60 * 60 * 1000;  // 24 horas

app.use((req, res, next) => {
  const now = Date.now();

  // usuário do app
  if (req.session?.userId) {
    if (!req.session._issuedAt) req.session._issuedAt = now;
    if (!req.session._lastSeen) req.session._lastSeen = now;

    const idle = now - req.session._lastSeen;
    const lived = now - req.session._issuedAt;

    if (lived > ABS_MS) {
      return req.session.destroy(() => res.redirect('/login?reason=expired'));
    }
    if (idle > IDLE_MS) {
      return req.session.destroy(() => res.redirect('/login?reason=idle'));
    }
    req.session._lastSeen = now;
  }

  // admin
  if (req.session?.adminAuthenticated) {
    if (!req.session._admIssuedAt) req.session._admIssuedAt = now;
    if (!req.session._admLastSeen) req.session._admLastSeen = now;

    const admIdle = now - req.session._admLastSeen;
    const admLived = now - req.session._admIssuedAt;

    if (admLived > ABS_MS) {
      req.session.adminAuthenticated = false;
      return res.redirect('/admin/login?reason=expired');
    }
    if (admIdle > IDLE_MS) {
      req.session.adminAuthenticated = false;
      return res.redirect('/admin/login?reason=idle');
    }
    req.session._admLastSeen = now;
  }

  next();
});

// (2) Sessão única por usuário: se o token da sessão ≠ token salvo no banco, derruba
app.use((req, res, next) => {
  if (req.session?.userId) {
    try {
      const u = DB.getUserById(req.session.userId);
      if (!u) {
        return req.session.destroy(() => res.redirect('/login'));
      }
      if (!req.session.sessionToken || u.session_token !== req.session.sessionToken) {
        // foi substituída por login em outro dispositivo
        return req.session.destroy(() => res.redirect('/login?reason=replaced'));
      }
    } catch (e) {
      console.error('[SESSION CHECK] erro:', e);
      return req.session.destroy(() => res.redirect('/login'));
    }
  }
  next();
});

// 8.1) Auth helper no res.locals
app.use((req, res, next) => {
  res.locals.auth = { user: null, isAdmin: !!req.session?.adminAuthenticated };
  if (req.session && req.session.userId) {
    try {
      const u = DB.getUserById(req.session.userId);
      if (u) {
        res.locals.auth.user = {
          id: u.id,
          name: u.name,
          email: u.email,
          plan: u.plan,
          status: u.status,
          access_expires_at: u.access_expires_at,
          mdf_mm: u.mdf_mm,
          travessa_mm: u.travessa_mm
        };
      }
    } catch (_) {}
  }
  next();
});

// --------- RATE LIMITERS ESPECÍFICOS ---------
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const passwordLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
// (NOVO) limiter exclusivo do login admin
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// --------- MIDDLEWARE DE AUTH ---------
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    const to = encodeURIComponent(req.originalUrl || '/conta');
    return res.redirect(`/login?next=${to}`);
  }
  next();
}

// --------- ROTAS PÚBLICAS ---------

// (a) Landing (home do site)
app.get('/', (req, res) => {
  const landingExists = fs.existsSync(path.join(__dirname, 'src', 'pages', 'landing.ejs'));
  if (landingExists) return res.render('pages/landing', { layout: 'layouts/marketing' });
  return res.render('pages/index');
});

// (b) Checkout (stub antigo) — permanece
app.post('/checkout', (req, res) => res.redirect('/inicio'));

// (c) Tela inicial do programa (se existir)
app.get('/inicio', (req, res) => {
  const homeExists = fs.existsSync(path.join(__dirname, 'src', 'pages', 'home.ejs'));
  if (homeExists) return res.render('pages/home', { layout: 'layouts/app' });
  return res
    .status(501)
    .send('Crie src/pages/home.ejs e src/layouts/app.ejs para usar /inicio.');
});

// Rotas de Configuração (protegidas)
app.get('/configuracao', requireAuth, (req, res) => {
  const u = DB.getUserById(req.session.userId);
  const cfg = {
    mdf_mm: Number.isInteger(u?.mdf_mm) ? u.mdf_mm : 15,
    travessa_mm: Number.isInteger(u?.travessa_mm) ? u.travessa_mm : 50
  };
  return res.render('pages/configuracao', {
    layout: 'layouts/app',
    cfg,
    ok: req.query.ok || null,
    erro: null
  });
});

app.post('/configuracao', requireAuth, (req, res) => {
  const toInt = x => parseInt(x, 10);
  const allowed = new Set([6, 15, 18]);

  let mdf = toInt(req.body.mdf_mm);
  let trav = toInt(req.body.travessa_mm);

  if (!allowed.has(mdf)) mdf = 15;
  if (!Number.isFinite(trav) || trav <= 0 || trav >= 10000) trav = 50;

  try {
    DB.updateUser(req.session.userId, { mdf_mm: mdf, travessa_mm: trav });
    return res.redirect('/configuracao?ok=1');
  } catch (e) {
    console.error('[CONFIG] erro:', e);
    return res.status(500).render('pages/configuracao', {
      layout: 'layouts/app',
      cfg: { mdf_mm: mdf, travessa_mm: trav },
      ok: null,
      erro: 'Erro ao salvar configuração. Tente novamente.'
    });
  }
});

// (d) Rota do app: PROJETO — lista + seleção de formulário
app.get('/projeto', (req, res) => {
  // Se o usuário ainda não criou um projeto pelo /projeto/novo, volta pro início
  if (!req.session.currentProject) {
    return res.redirect('/inicio');
  }
  // garante o array de itens
  if (!Array.isArray(req.session.currentProject.items)) {
    req.session.currentProject.items = [];
  }

  const kind   = (req.query.kind || '').trim() || null;   // qual formulário abrir
  const editId = (req.query.edit || '').trim() || null;   // modo edição
  let editItem = null;

  if (editId) {
    editItem = req.session.currentProject.items.find(x => String(x.id) === String(editId)) || null;
  }

  const project = req.session.currentProject;
  const ok  = req.query.ok  || null;
  const err = req.query.err || null;

  return res.render('pages/projeto', {
    layout: 'layouts/app',
    project,
    kind,
    editItem,
    ok,
    err
  });
});

// Helpers locais do Projeto
function nextIndex(items) {
  return (items?.length || 0) + 1;
}
function pad2(n) {
  return String(n).padStart(2, '0');
}
function labelFor(kind, index) {
  // nomes sem acento p/ ficar padronizado
  const base = (kind === 'inferior_individual')
    ? 'armario inferior (modulo individual)'
    : (kind === 'inferior_conjunto')
      ? 'armario inferior (conjunto)'
      : kind;
  return `${pad2(index)}-${base}`;
}

// Inserir item no projeto
app.post('/projeto/item/add', (req, res) => {
  if (!req.session.currentProject) return res.redirect('/inicio');
  const items = (req.session.currentProject.items ||= []);

  const kind = (req.body.kind || '').trim();

  // dimensões (inteiros)
  const largura = parseInt(req.body.largura, 10) || 0;
  const altura  = parseInt(req.body.altura, 10)  || 0;
  const prof    = parseInt(req.body.profundidade, 10) || 0;
  if (largura <= 0 || altura <= 0 || prof <= 0) {
    return res.redirect(`/projeto?kind=${encodeURIComponent(kind)}&err=dim`);
  }

  // cores
  const corCaixa    = (req.body.cor_caixa || 'Branco TX').trim();
  const corFrentes  = (req.body.cor_frentes || 'Branco TX').trim();
  const corLaterais = (req.body.cor_laterais || 'Branco TX').trim();

  const index = nextIndex(items);
  const id = uuidv4();

  // monta payload por tipo
  let options = {};
  if (kind === 'inferior_individual') {
    // exclusividade: apenas um dos grupos
    const gOn  = req.body.gaveteiro_on === '1';
    const ptOn = req.body.porta_tempero_on === '1';
    const bOn  = req.body.basculante_on === '1';
    const pgOn = req.body.portas_on === '1';

    // força exclusividade server-side
    const pickOne = [gOn, ptOn, bOn, pgOn].findIndex(v => v); // qual está ativo (-1 se nenhum)
    const only = (i) => i === pickOne;

    options = {
      gaveteiro: only(0) ? {
        ativo: true,
        tipo: (req.body.gaveteiro_tipo === 'gavetao' ? 'gavetao' : 'normal'),
        quantidade: Math.max(1, parseInt(req.body.gaveteiro_qt,10) || 1)
      } : { ativo:false },
      portaTempero: only(1) ? {
        ativo: true,
        tipo: (req.body.pt_tipo === 'aramado' ? 'aramado' : 'mdf')
      } : { ativo:false },
      basculante: only(2) ? {
        ativo: true,
        qtde: Math.max(1, parseInt(req.body.basculante_qt,10) || 1)
      } : { ativo:false },
      portasGiro: only(3) ? {
        ativo: true,
        qtde: Math.max(1, parseInt(req.body.portas_qt,10) || 1),
        prateleiras: (req.body.prat_on === '1')
          ? { ativo: true, qtde: Math.max(1, parseInt(req.body.prat_qt,10) || 1) }
          : { ativo:false }
      } : { ativo:false }
    };
  } else if (kind === 'inferior_conjunto') {
    const lateralDuplada = (req.body.lateral_duplada === '1');

    // gaveteiros (módulos) dinâmicos
    const modCount = Math.max(0, parseInt(req.body.gav_mod_count,10) || 0);
    const gaveteiros = [];
    let somaLarg = 0;
    for (let i=1;i<=modCount;i++){
      const w = Math.max(0, parseInt(req.body[`gav_mod_${i}_largura`],10) || 0);
      const q = Math.max(1, parseInt(req.body[`gav_mod_${i}_qt`],10) || 1);
      if (w > 0) {
        gaveteiros.push({ ordem:i, largura:w, gavetas:q });
        somaLarg += w;
      }
    }
    if (somaLarg > largura) {
      return res.redirect(`/projeto?kind=inferior_conjunto&err=largura_gaveteiros`);
    }

    const ptOn = req.body.porta_tempero_on === '1';
    const pt   = ptOn ? {
      ativo: true,
      largura: Math.max(0, parseInt(req.body.pt_largura,10) || 0),
      tipo: (req.body.pt_tipo === 'aramado' ? 'aramado' : 'mdf')
    } : { ativo:false };

    const bOn = req.body.basculante_on === '1';
    const b   = bOn ? {
      ativo:true,
      qtde: Math.max(1, parseInt(req.body.basculante_qt,10) || 1),
      largura: Math.max(0, parseInt(req.body.basculante_largura,10) || 0)
    } : { ativo:false };

    const lava = (req.body.lava_on === '1')
      ? { ativo:true, largura: Math.max(0, parseInt(req.body.lava_largura,10) || 0) }
      : { ativo:false };

    const portasQt = Math.max(0, parseInt(req.body.portas_qt,10) || 0);
    const pratsQt  = Math.max(0, parseInt(req.body.prateleiras_qt,10) || 0);

    options = {
      lateralDuplada,
      gaveteiros,
      portaTempero: pt,
      basculante: b,
      vaoLavaLouca: lava,
      portas: portasQt,
      prateleiras: pratsQt
    };
  } else {
    return res.redirect('/projeto?err=tipo');
  }

  const item = {
    id,
    index,
    kind,
    label: labelFor(kind, index),
    largura, altura, profundidade: prof,
    cores: { caixa: corCaixa, frentes: corFrentes, laterais: corLaterais },
    options
  };

  items.push(item);
  return res.redirect('/projeto?ok=add');
});

// Atualizar item existente
app.post('/projeto/item/update', (req, res) => {
  if (!req.session.currentProject) return res.redirect('/inicio');
  const items = (req.session.currentProject.items ||= []);
  const id = (req.body.id || '').trim();
  const idx = items.findIndex(x => String(x.id) === String(id));
  if (idx === -1) return res.redirect('/projeto?err=notfound');

  // reaproveita o mesmo handler de add (mas preserva index/label)
  const kind = items[idx].kind;
  req.body.kind = kind; // força consistência

  // validações iguais às do add
  const largura = parseInt(req.body.largura, 10) || 0;
  const altura  = parseInt(req.body.altura, 10)  || 0;
  const prof    = parseInt(req.body.profundidade, 10) || 0;
  if (largura <= 0 || altura <= 0 || prof <= 0) {
    return res.redirect(`/projeto?edit=${encodeURIComponent(id)}&err=dim`);
  }

  const corCaixa    = (req.body.cor_caixa || 'Branco TX').trim();
  const corFrentes  = (req.body.cor_frentes || 'Branco TX').trim();
  const corLaterais = (req.body.cor_laterais || 'Branco TX').trim();

  let options = {};
  if (kind === 'inferior_individual') {
    const gOn  = req.body.gaveteiro_on === '1';
    const ptOn = req.body.porta_tempero_on === '1';
    const bOn  = req.body.basculante_on === '1';
    const pgOn = req.body.portas_on === '1';
    const pickOne = [gOn, ptOn, bOn, pgOn].findIndex(v => v);
    const only = (i) => i === pickOne;

    options = {
      gaveteiro: only(0) ? {
        ativo:true,
        tipo: (req.body.gaveteiro_tipo === 'gavetao' ? 'gavetao' : 'normal'),
        quantidade: Math.max(1, parseInt(req.body.gaveteiro_qt,10) || 1)
      } : { ativo:false },
      portaTempero: only(1) ? {
        ativo:true,
        tipo: (req.body.pt_tipo === 'aramado' ? 'aramado' : 'mdf')
      } : { ativo:false },
      basculante: only(2) ? {
        ativo:true,
        qtde: Math.max(1, parseInt(req.body.basculante_qt,10) || 1)
      } : { ativo:false },
      portasGiro: only(3) ? {
        ativo:true,
        qtde: Math.max(1, parseInt(req.body.portas_qt,10) || 1),
        prateleiras: (req.body.prat_on === '1')
          ? { ativo:true, qtde: Math.max(1, parseInt(req.body.prat_qt,10) || 1) }
          : { ativo:false }
      } : { ativo:false }
    };
  } else if (kind === 'inferior_conjunto') {
    const lateralDuplada = (req.body.lateral_duplada === '1');
    const modCount = Math.max(0, parseInt(req.body.gav_mod_count,10) || 0);
    const gaveteiros = [];
    let soma = 0;
    for (let i=1;i<=modCount;i++){
      const w = Math.max(0, parseInt(req.body[`gav_mod_${i}_largura`],10) || 0);
      const q = Math.max(1, parseInt(req.body[`gav_mod_${i}_qt`],10) || 1);
      if (w>0){ gaveteiros.push({ ordem:i, largura:w, gavetas:q }); soma += w; }
    }
    if (soma > largura) {
      return res.redirect(`/projeto?edit=${encodeURIComponent(id)}&err=largura_gaveteiros`);
    }

    const ptOn = req.body.porta_tempero_on === '1';
    const pt   = ptOn ? {
      ativo:true,
      largura: Math.max(0, parseInt(req.body.pt_largura,10) || 0),
      tipo: (req.body.pt_tipo === 'aramado' ? 'aramado' : 'mdf')
    } : { ativo:false };

    const bOn = req.body.basculante_on === '1';
    const b   = bOn ? {
      ativo:true,
      qtde: Math.max(1, parseInt(req.body.basculante_qt,10) || 1),
      largura: Math.max(0, parseInt(req.body.basculante_largura,10) || 0)
    } : { ativo:false };

    const lava = (req.body.lava_on === '1')
      ? { ativo:true, largura: Math.max(0, parseInt(req.body.lava_largura,10) || 0) }
      : { ativo:false };

    const portasQt = Math.max(0, parseInt(req.body.portas_qt,10) || 0);
    const pratsQt  = Math.max(0, parseInt(req.body.prateleiras_qt,10) || 0);

    options = {
      lateralDuplada,
      gaveteiros,
      portaTempero: pt,
      basculante: b,
      vaoLavaLouca: lava,
      portas: portasQt,
      prateleiras: pratsQt
    };
  }

  // aplica atualização preservando id/index/label
  items[idx] = {
    ...items[idx],
    largura, altura, profundidade: prof,
    cores: { caixa: corCaixa, frentes: corFrentes, laterais: corLaterais },
    options
  };

  return res.redirect('/projeto?ok=upd');
});

// Excluir item
app.post('/projeto/item/delete/:id', (req, res) => {
  if (!req.session.currentProject) return res.redirect('/inicio');
  const items = (req.session.currentProject.items ||= []);
  const id = (req.params.id || '').trim();
  const before = items.length;
  req.session.currentProject.items = items.filter(x => String(x.id) !== String(id));

  // renumera índices/labels
  req.session.currentProject.items.forEach((it, i) => {
    it.index = i+1;
    it.label = labelFor(it.kind, it.index);
  });

  const ok = (before !== req.session.currentProject.items.length) ? 'del' : null;
  return res.redirect(ok ? `/projeto?ok=${ok}` : '/projeto');
});

// (e) Cadastro (GET)
app.get('/cadastro', (req, res) => {
  const plano = (req.query.plano === 'mensal') ? 'mensal' : 'anual';
  res.render('pages/cadastro', {
    layout: 'layouts/marketing',
    step: 'form',
    plano,
    data: {},
    erro: null
  });
});

// (f) Cadastro (POST) — inclui RENOVAÇÃO pelo mesmo e-mail
app.post('/cadastro', async (req, res) => {
  try {
    const sane  = s => (typeof s === 'string' ? s.trim() : '');
    const plano = (req.body.plano === 'mensal') ? 'mensal' : 'anual';

    const nome    = sane(req.body.nome);
    const empresa = sane(req.body.empresa);
    const email   = sane(req.body.email).toLowerCase();
    const senha   = sane(req.body.senha);
    const senha2  = sane(req.body.senha2);

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!nome || !emailOk || senha.length < 6) {
      return res.status(400).render('pages/cadastro', {
        layout: 'layouts/marketing',
        step: 'form',
        plano,
        data: { nome, empresa, email },
        erro: !emailOk
          ? 'E-mail inválido.'
          : 'Preencha os campos obrigatórios (senha com 6+ caracteres).'
      });
    }
    if (senha !== senha2) {
      return res.status(400).render('pages/cadastro', {
        layout: 'layouts/marketing',
        step: 'form',
        plano,
        data: { nome, empresa, email },
        erro: 'As senhas não coincidem.'
      });
    }

    const amount_cents = (plano === 'mensal') ? 5990 : (4190 * 12);

    // Usuário já existe?
    const existing = DB.getUserByEmail(email);
    if (existing) {
      // senha precisa conferir para renovar usando o mesmo e-mail
      const ok = await bcrypt.compare(senha, existing.password_hash || '');
      if (!ok) {
        return res.status(400).render('pages/cadastro', {
          layout: 'layouts/marketing',
          step: 'form',
          plano,
          data: { nome, empresa, email },
          erro: 'E-mail já cadastrado. A senha não confere.'
        });
      }

      // se já tiver pagamento pendente, continua nele
      const pending = DB.getPendingPaymentForUser(existing.id);
      if (pending) return res.redirect(`/pagamento/${pending.order_ref}`);

      // se assinatura ainda está ativa, leva direto para o app
      if (isActive(existing)) {
        await startUserSession(req, existing.id, false);
        return res.redirect('/inicio');
      }

      // expirado/inativo → cria nova ordem
      const order_ref = uuidv4();
      DB.createPayment({
        user_id: existing.id,
        provider: 'link',
        order_ref,
        amount_cents,
        plan: plano
      });
      req.session.pendingOrderRef = order_ref;
      return res.redirect(`/pagamento/${order_ref}`);
    }

    // novo usuário
    const password_hash = await bcrypt.hash(senha, 12);
    const userId = DB.createUser({
      name: nome,
      company: empresa,
      email,
      password_hash,
      plan: plano
    });

    const order_ref = uuidv4();
    DB.createPayment({
      user_id: userId,
      provider: 'link',
      order_ref,
      amount_cents,
      plan: plano
    });

    req.session.pendingOrderRef = order_ref;
    return res.redirect(`/pagamento/${order_ref}`);

  } catch (err) {
    console.error(err);
    return res.status(500).render('pages/cadastro', {
      layout: 'layouts/marketing',
      step: 'form',
      plano: (req.body.plano === 'mensal' ? 'mensal' : 'anual'),
      data: { nome: req.body?.nome, empresa: req.body?.empresa, email: req.body?.email },
      erro: 'Erro ao processar cadastro. Tente novamente.'
    });
  }
});

// (g) Página de pagamento
app.get('/pagamento/:ref', (req, res) => {
  const ref = req.params.ref;
  const pay = DB.getPaymentByOrderRef(ref);
  if (!pay) return res.status(404).send('Ordem não encontrada.');

  const amountBRL = (pay.amount_cents / 100).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
  const user = DB.getUserById(pay.user_id);
  const plan = pay.plan || user?.plan || 'anual';

  const links = { mercadopago: '#', infinitepay: '#' };

  res.render('pages/pagamento', {
    layout: 'layouts/marketing',
    orderRef: ref,
    amountBRL,
    plan,
    devSimulate: !IS_PROD,
    links
  });
});

// (h) Simular pagamento (DEV) → ativa e loga (com rota debug opcional)
app.get('/dev/pagar/:ref', async (req, res) => {
  try {
    if (IS_PROD) return res.status(403).send('Indisponível em produção.');

    const ref = req.params.ref;
    const pay = DB.getPaymentByOrderRef(ref);
    if (!pay) return res.status(404).send('Ordem não encontrada.');

    if (pay.status !== 'paid') {
      DB.markPaymentPaid(ref, 'dev-simulated');
      const days = (pay.plan === 'mensal') ? 30 : 365;
      const expires = new Date();
      expires.setDate(expires.getDate() + days);
      DB.activateUser(pay.user_id, expires.toISOString());
    }

    await startUserSession(req, pay.user_id, false);
    return res.redirect('/conta');
  } catch (e) {
    console.error('[DEV/PAGAR] erro inesperado:', e);
    return res.status(500).send('Falha ao simular pagamento. Veja o console do servidor.');
  }
});

// Debug opcional (JSON)
app.get('/dev/pagar/:ref/debug', (req, res) => {
  try {
    const ref = req.params.ref;
    const pay = DB.getPaymentByOrderRef(ref);
    if (!pay) return res.json({ ok:false, error:'not found' });

    if (pay.status !== 'paid') {
      DB.markPaymentPaid(ref, 'dev-simulated');
      const days = (pay.plan === 'mensal') ? 30 : 365;
      const expires = new Date();
      expires.setDate(expires.getDate() + days);
      DB.activateUser(pay.user_id, expires.toISOString());
    }
    return res.json({ ok:true, pay, user: DB.getUserById(pay.user_id) });
  } catch (e) {
    return res.json({ ok:false, error:e.message, stack:String(e) });
  }
});

// (i) Login — GET (form)
app.get('/login', (req, res) => {
  res.render('pages/login', {
    layout: 'layouts/marketing',
    erro: null,
    next: req.query.next || '/conta'
  });
});

// (i.1) Login — POST
app.post('/login', loginLimiter, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const senha = (req.body.senha || '').trim();
  const nextUrl = (req.body.next || '/conta');
  const remember = (req.body.remember === '1');

  const user = DB.getUserByEmail(email);
  if (!user) {
    return res.status(401).render('pages/login', {
      layout: 'layouts/marketing',
      erro: 'Credenciais inválidas.',
      next: nextUrl
    });
  }
  const ok = await bcrypt.compare(senha, user.password_hash || '');
  if (!ok) {
    return res.status(401).render('pages/login', {
      layout: 'layouts/marketing',
      erro: 'Credenciais inválidas.',
      next: nextUrl
    });
  }

  await startUserSession(req, user.id, remember);

  if (isActive(user)) return res.redirect('/inicio');
  return res.redirect('/conta?expired=1');
});

// (j) Conta (requer login)
app.get('/conta', requireAuth, (req, res) => {
  const user = DB.getUserById(req.session.userId);
  if (!user) return res.redirect('/');
  const expired = !isActive(user);
  const pending = DB.getPendingPaymentForUser(user.id);
  const ok  = req.query.ok  || null;
  const err = req.query.err || null;
  res.render('pages/conta', { layout: 'layouts/app', user, expired, pending, ok, err });
});

// Atualizar perfil (nome, empresa, e-mail)
app.post('/conta/profile', requireAuth, (req, res) => {
  const sane  = s => (typeof s === 'string' ? s.trim() : '');
  const name  = sane(req.body.name);
  const company = sane(req.body.company);
  const email = sane(req.body.email).toLowerCase();

  // validações simples
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!name || !emailOk) {
    return res.redirect('/conta?err=invalid_profile');
  }

  const userId = req.session.userId;

  // e-mail único: se existir e não for deste usuário, barrar
  const another = DB.getUserByEmail(email);
  if (another && another.id !== userId) {
    return res.redirect('/conta?err=email_taken');
  }

  try {
    DB.updateUser(userId, { name, company, email });
    return res.redirect('/conta?ok=profile');
  } catch (e) {
    console.error('[PROFILE] update error:', e);
    return res.redirect('/conta?err=profile_failed');
  }
});

// Trocar senha (gira token/sessão)
app.post('/conta/senha', requireAuth, passwordLimiter, async (req, res) => {
  try {
    const sane = s => (typeof s === 'string' ? s.trim() : '');
    const atual    = sane(req.body.atual);
    const nova     = sane(req.body.nova);
    const confirma = sane(req.body.confirma);

    if (!nova || nova.length < 6) {
      return res.redirect('/conta?err=pass_short');
    }
    if (nova !== confirma) {
      return res.redirect('/conta?err=pass_mismatch');
    }

    const user = DB.getUserById(req.session.userId);
    if (!user) return res.redirect('/login');

    // Se já existe senha cadastrada, exige a senha atual correta
    if (user.password_hash) {
      const ok = await bcrypt.compare(atual, user.password_hash || '');
      if (!ok) return res.redirect('/conta?err=pass_current');
    }

    const hash = await bcrypt.hash(nova, 12);
    DB.updateUserPassword(user.id, hash);

    // gira token e sessão (invalida outros dispositivos)
    await startUserSession(req, user.id, false);

    return res.redirect('/conta?ok=pass');
  } catch (e) {
    console.error('[PASS] erro:', e);
    return res.redirect('/conta?err=pass_failed');
  }
});

// >>> NOVA ROTA: Excluir conta do usuário (com verificação de senha)
app.post('/conta/excluir', requireAuth, async (req, res) => {
  try {
    const pass = (req.body.password || '').trim();
    const u = DB.getUserById(req.session.userId);
    if (!u) return res.redirect('/login');

    // exige senha correta (se houver hash cadastrado)
    if (u.password_hash) {
      const ok = await bcrypt.compare(pass, u.password_hash || '');
      if (!ok) return res.redirect('/conta?err=del_pass');
    }

    try { DB.recordDeletion({ user_id: u.id, email: u.email, actor: 'user' }); } catch (_) {}
    DB.deleteUser(u.id);

    // encerra a sessão e redireciona
    req.session.regenerate(() => res.redirect('/?deleted=1'));
  } catch (e) {
    console.error('[DELETE ACCOUNT] erro:', e);
    return res.redirect('/conta?err=del_failed');
  }
});

app.get('/logout', (req, res) => {
  try {
    if (req.session?.userId) {
      DB.clearUserSession(req.session.userId);
    }
  } catch (_) {}
  req.session.regenerate(() => res.redirect('/'));
});

// Renovar/criar ordem de pagamento a partir da conta logada
app.post('/renovar', requireAuth, (req, res) => {
  const plan = (req.body.plan === 'mensal') ? 'mensal' : 'anual';
  const userId = req.session.userId;

  // Reuso de ordem pendente se existir
  const pending = DB.getPendingPaymentForUser(userId);
  if (pending) return res.redirect(`/pagamento/${pending.order_ref}`);

  const amount_cents = (plan === 'mensal') ? 5990 : (4190 * 12);
  const order_ref = uuidv4();
  DB.createPayment({
    user_id: userId,
    provider: 'link',
    order_ref,
    amount_cents,
    plan
  });
  return res.redirect(`/pagamento/${order_ref}`);
});

// Ajuda -> YouTube
app.get('/ajuda', (req, res) => {
  res.redirect('https://www.youtube.com/@4deng');
});

// Criar projeto (MVP) – guarda numa sessão e abre /projeto
app.post('/projeto/novo', (req, res) => {
  const sane = s => (typeof s === 'string' ? s.trim() : '');
  const cliente  = sane(req.body.cliente);
  const ambiente = sane(req.body.ambiente);
  if (!cliente || !ambiente) return res.redirect('/inicio');

  // guarda temporariamente para a tela de projeto (só para MVP)
  req.session.currentProject = { cliente, ambiente, createdAt: new Date().toISOString() };
  return res.redirect('/projeto');
});

// >>> (d.1) Rota do app: RELATÓRIO — placeholder (mantém link funcionando)
app.get('/relatorio', (req, res) => {
  return res.render('pages/relatorio', { layout: 'layouts/app' });
});

// --------- ROTAS ADMIN ---------
function requireAdmin(req, res, next) {
  if (!ADMIN_PASS) return res.status(503).send('Admin desabilitado: defina ADMIN_PASS no .env');
  if (!req.session?.adminAuthenticated) return res.redirect('/admin/login');

  // Anti-cache para páginas administrativas
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  return next();
}

// Login admin
app.get('/admin/login', (req, res) => {
  if (!ADMIN_PASS) return res.status(503).send('Admin desabilitado: defina ADMIN_PASS no .env');
  res.render('pages/admin/login', {
    layout: 'layouts/admin',
    erro: null
  });
});

app.post('/admin/login', adminLoginLimiter, (req, res) => {
  if (!ADMIN_PASS) return res.status(503).send('Admin desabilitado: defina ADMIN_PASS no .env');
  const pass = (req.body.senha || '').trim();

  if (!(pass && pass === ADMIN_PASS)) {
    return res.status(401).render('pages/admin/login', {
      layout: 'layouts/admin',
      erro: 'Senha inválida.'
    });
  }

  // Regenera ID de sessão para evitar fixation
  req.session.regenerate(err => {
    if (err) {
      console.error('[ADMIN LOGIN] falha ao regenerar sessão:', err);
      return res.status(500).render('pages/admin/login', {
        layout: 'layouts/admin',
        erro: 'Falha de sessão. Tente novamente.'
      });
    }
    req.session.adminAuthenticated = true;
    req.session._admIssuedAt = Date.now();
    req.session._admLastSeen = Date.now();
    return res.redirect('/admin');
  });
});

// Logout admin — via POST (recomendado)
app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session.adminAuthenticated = false;
  req.session._admIssuedAt = null;
  req.session._admLastSeen = null;
  req.session.regenerate(() => res.redirect('/'));
});

// (compatibilidade) Logout admin por GET
app.get('/admin/logout', (req, res) => {
  req.session.adminAuthenticated = false;
  req.session._admIssuedAt = null;
  req.session._admLastSeen = null;
  req.session.regenerate(() => res.redirect('/'));
});

// Dashboard (lista + busca/paginação)
app.get('/admin', requireAdmin, (req, res) => {
  const q = (req.query.q || '').trim();
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = 25;
  const offset = (page - 1) * limit;

  const users = DB.searchUsers({ q, limit, offset });
  const hasNext = users.length === limit;

  res.render('pages/admin/index', {
    layout: 'layouts/admin',
    q, users, page, hasNext
  });
});

// ===== Admin: Editar usuário (GET) =====
app.get('/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = DB.getUserById(id);
  if (!user) return res.status(404).send('Usuário não encontrado.');
  const okMsg = req.query.ok ? 'Dados atualizados.' : null;
  return res.render('pages/admin/admin-user', {
    layout: 'layouts/admin',
    user,
    erro: null,
    ok: okMsg
  });
});

// ===== Admin: Editar usuário (POST) =====
app.post('/admin/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const current = DB.getUserById(id);
  if (!current) return res.status(404).send('Usuário não encontrado.');

  const sane = s => (typeof s === 'string' ? s.trim() : '');
  const email = sane(req.body.email).toLowerCase();

  // normaliza data: aceita YYYY-MM-DD ou DD/MM/YYYY
  let expRaw = sane(req.body.access_expires_at);
  let expISO = null;
  if (expRaw) {
    if (/^\d{4}-\d{2}-\d{2}$/.test(expRaw)) {
      expISO = expRaw;
    } else if (/^\d{2}\/\d{2}\/\d{4}$/.test(expRaw)) {
      const [d, m, y] = expRaw.split('/');
      expISO = `${y}-${m}-${d}`;
    }
  }

  const payload = {
    name: sane(req.body.name),
    company: sane(req.body.company),
    email,
    plan: sane(req.body.plan),
    status: sane(req.body.status),
    access_expires_at: expISO || null
  };

  // regras: vitalício => sem validade; ativo => precisa de validade
  if (payload.status === 'vitalicio') {
    // vai limpar de fato após o update (ver logo abaixo)
    payload.access_expires_at = null;
  }
  if (payload.status === 'active' && !payload.access_expires_at) {
    const viewUser = { ...current, ...payload };
    return res.render('pages/admin/admin-user', {
      layout: 'layouts/admin',
      user: viewUser,
      erro: 'Para status "Ativo", informe a data de validade.',
      ok: null
    });
  }

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email || '');
  if (!emailOk) {
    const viewUser = { ...current, ...payload };
    return res.render('pages/admin/admin-user', {
      layout: 'layouts/admin',
      user: viewUser,
      erro: 'E-mail inválido.',
      ok: null
    });
  }

  try {
    DB.updateUser(id, payload);

    // se marcou vitalício, garante que access_expires_at fica NULL (limpa de verdade)
    if (payload.status === 'vitalicio') {
      try { DB.db.prepare(`UPDATE users SET access_expires_at = NULL WHERE id = ?`).run(id); } catch (_) {}
    }

    // se admin informou nova senha, valida e aplica
    const newPass = sane(req.body.new_password);
    const conf    = sane(req.body.confirm_password);
    if (newPass || conf) {
      if (newPass.length < 6) {
        const viewUser = DB.getUserById(id);
        return res.render('pages/admin/admin-user', {
          layout: 'layouts/admin',
          user: viewUser,
          erro: 'A nova senha deve ter pelo menos 6 caracteres.',
          ok: null
        });
      }
      if (newPass !== conf) {
        const viewUser = DB.getUserById(id);
        return res.render('pages/admin/admin-user', {
          layout: 'layouts/admin',
          user: viewUser,
          erro: 'A confirmação da nova senha não confere.',
          ok: null
        });
      }
      const hash = await bcrypt.hash(newPass, 12);
      DB.updateUserPassword(id, hash);
    }

    return res.redirect(`/admin/users/${id}?ok=1`);
  } catch (e) {
    let msg = 'Erro ao atualizar. Verifique e tente novamente.';
    if (e?.code === 'EMAIL_TAKEN' || /SQLITE_CONSTRAINT/i.test(String(e?.message))) {
      msg = 'Este e-mail já está em uso por outro cadastro.';
    }
    const viewUser = { ...current, ...payload };
    return res.render('pages/admin/admin-user', {
      layout: 'layouts/admin',
      user: viewUser,
      erro: msg,
      ok: null
    });
  }
});

// Admin: Excluir (individual)
app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const u  = DB.getUserById(id);
    if (u) {
      try { DB.recordDeletion({ user_id: u.id, email: u.email, actor: 'admin' }); } catch (_) {}
    }
    DB.deleteUser(id);
    return res.redirect('/admin?q=' + encodeURIComponent(req.query.q || ''));
  } catch (e) {
    console.error(e);
    return res.status(500).send('Erro ao excluir usuário.');
  }
});

// Admin: Excluir em lote — revisão
app.post('/admin/users/bulk-review', requireAdmin, (req, res) => {
  let ids = req.body.ids;
  if (!ids) return res.redirect('/admin');
  if (!Array.isArray(ids)) ids = [ids];

  const users = ids.map(id => DB.getUserById(id)).filter(Boolean);
  if (users.length === 0) return res.redirect('/admin');

  res.render('pages/admin/admin-bulk-review', {
    layout: 'layouts/admin',
    users
  });
});

// Admin: Excluir em lote — confirmar
app.post('/admin/users/bulk-delete', requireAdmin, (req, res) => {
  let ids = req.body.ids;
  if (!ids) return res.redirect('/admin');
  if (!Array.isArray(ids)) ids = [ids];

  try {
    DB.deleteUsers(ids.map(x => parseInt(x, 10)).filter(Boolean));
  } catch (e) {
    console.error(e);
    return res.status(500).send('Erro ao excluir selecionados.');
  }
  return res.redirect('/admin');
});

// Detalhe do usuário (com pagamentos)
app.get('/admin/user/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = DB.getUserById(id);
  if (!user) return res.status(404).send('Usuário não encontrado.');
  const payments = DB.getPaymentsByUser(id);
  res.render('pages/admin/user', {
    layout: 'layouts/admin',
    user, payments
  });
});

// 4D Conta — GET (mostra o formulário)
app.get('/admin/4d-conta', requireAdmin, (req, res) => {
  const vital = DB.getFirstVitalicio() || null;
  res.render('pages/admin/4d-conta', {
    layout: 'layouts/admin',
    vital,
    erro: null,
    ok: req.query.ok ? 'Conta salva com sucesso.' : null
  });
});

// 4D Conta — POST (criar/atualizar conta vitalícia)
app.post('/admin/4d-conta', requireAdmin, async (req, res) => {
  try {
    const sane = s => (typeof s === 'string' ? s.trim() : '');
    const name  = sane(req.body.name);
    const email = sane(req.body.email).toLowerCase();
    const pass  = sane(req.body.password);
    const conf  = sane(req.body.confirm);

    if (!name || !email) {
      return res.status(400).render('pages/admin/4d-conta', {
        layout: 'layouts/admin',
        vital: { name, email, status: 'vitalicio' },
        erro: 'Preencha nome e e-mail.',
        ok: null
      });
    }
    if (pass || conf) {
      if (pass.length < 6) {
        return res.status(400).render('pages/admin/4d-conta', {
          layout: 'layouts/admin',
          vital: { name, email, status: 'vitalicio' },
          erro: 'A senha precisa ter pelo menos 6 caracteres.',
          ok: null
        });
      }
      if (pass !== conf) {
        return res.status(400).render('pages/admin/4d-conta', {
          layout: 'layouts/admin',
          vital: { name, email, status: 'vitalicio' },
          erro: 'A confirmação da senha não confere.',
          ok: null
        });
      }
    }

    // Se existir, atualiza; senão cria
    const existing = DB.getUserByEmail(email);
    if (existing) {
      const payload = {
        name,
        email,
        status: 'vitalicio',
        plan: existing.plan || null,
        access_expires_at: null
      };
      DB.updateUser(existing.id, payload);
      // limpa validade mesmo se já havia
      try { DB.db.prepare(`UPDATE users SET access_expires_at = NULL WHERE id = ?`).run(existing.id); } catch (_) {}
      if (pass) {
        const hash = await bcrypt.hash(pass, 12);
        DB.updateUserPassword(existing.id, hash);
      }
    } else {
      const hash = pass ? await bcrypt.hash(pass, 12) : null;
      const newId = DB.createUser({
        name,
        company: null,
        email,
        password_hash: hash,
        plan: null
      });
      // força vitalício e zera validade
      DB.updateUser(newId, { status: 'vitalicio', access_expires_at: null });
      try { DB.db.prepare(`UPDATE users SET access_expires_at = NULL WHERE id = ?`).run(newId); } catch (_) {}
    }

    return res.redirect('/admin/4d-conta?ok=1');
  } catch (e) {
    console.error('[4D-CONTA] erro:', e);
    return res.status(500).render('pages/admin/4d-conta', {
      layout: 'layouts/admin',
      vital: null,
      erro: 'Falha ao salvar a conta. Tente novamente.',
      ok: null
    });
  }
});

// Relatório
app.get('/admin/relatorio', requireAdmin, (req, res) => {
  try {
    const total       = DB.countAllUsers();
    const ativas      = DB.countActiveNow();
    const inativas    = DB.countInactiveNow();
    const planoAnual  = DB.countPlan('anual');
    const planoMensal = DB.countPlan('mensal');
    const del         = DB.getDeletionSummary();

    res.render('pages/admin/relatorio', {
      layout: 'layouts/admin',
      stats: {
        total, ativas, inativas,
        planoAnual, planoMensal,
        deletadas_admin: del.by_admin,
        deletadas_usuario: del.by_user,
        deletadas_total: del.total
      }
    });
  } catch (e) {
    console.error('[RELATÓRIO] erro:', e);
    res.status(500).send('Erro ao gerar relatório.');
  }
});

// 10) 404 e erros
app.use((req, res) => res.status(404).send('Página não encontrada'));
app.use((err, req, res, _next) => {
  if (err.code === 'EBADCSRFTOKEN') return res.status(403).send('Sessão expirada. Recarregue a página.');
  console.error(err);
  res.status(500).send('Erro interno');
});

// 11) Start
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});
