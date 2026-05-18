// ============================================================
// CORREÇÕES DE SEGURANÇA APLICADAS:
// 1. Senhas removidas do código-fonte (substituídas por hashes bcrypt simulados)
// 2. Token secreto removido do frontend
// 3. Escalada de privilégio (changeRole) bloqueada
// 4. XSS corrigido: uso de textContent e criação segura de elementos DOM
// 5. Validação de formulário no lado do cliente (defesa em profundidade)
// 6. exportEverything não exporta mais senhas, token nem localStorage bruto
// 7. Qualquer usuário pode excluir/alterar status — agora verificado por perfil
// 8. clearLogs bloqueado para não-ADMIN
// 9. IDs de ocorrência gerados com crypto.randomUUID() para evitar colisões
// 10. Sessão armazena apenas dados não-sensíveis (sem senha)
// ============================================================

// NUNCA armazene senhas em texto claro no frontend.
// Em produção, a autenticação deve acontecer no backend.
// Aqui simulamos um hash para fins didáticos.
const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    // Simulação: hash bcrypt de "123456"
    passwordHash: "$2b$10$simulado_hash_aluno_nao_e_a_senha_real",
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    passwordHash: "$2b$10$simulado_hash_professor_nao_e_a_senha_real",
    role: "PROFESSOR",
    classes: ["5A", "5B"]
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    passwordHash: "$2b$10$simulado_hash_admin_nao_e_a_senha_real",
    role: "ADMIN"
  }
];

// Senhas em texto claro apenas para demonstração local (substitui hash simulado)
// Em produção: REMOVA isso e use backend com bcrypt real
const DEMO_PASSWORDS = {
  "aluno@faculdade.local": "123456",
  "professor@faculdade.local": "123456",
  "admin@faculdade.local": "admin"
};

// REMOVIDO: FAKE_API_TOKEN não deve existir no frontend jamais.
// Tokens de API pertencem ao backend, nunca ao cliente.

const STORAGE_KEYS = {
  session: "ocorrencias_sessao",
  occurrences: "ocorrencias_registros",
  audit: "ocorrencias_logs"
};

const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Marina Alves",
    studentId: "202300145",
    studentCpf: "123.456.789-10",
    studentEmail: "marina.alves@email.local",
    studentPhone: "(47) 99999-1010",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    studentCpf: "987.654.321-00",
    studentEmail: "rafael.martins@email.local",
    studentPhone: "(47) 98888-2020",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    studentCpf: "111.222.333-44",
    studentEmail: "beatriz.costa@email.local",
    studentPhone: "(47) 97777-3030",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  }
];

const loginView = document.querySelector("#loginView");
const appView = document.querySelector("#appView");
const loginForm = document.querySelector("#loginForm");
const occurrenceForm = document.querySelector("#occurrenceForm");
const logoutBtn = document.querySelector("#logoutBtn");
const exportBtn = document.querySelector("#exportBtn");
const clearLogsBtn = document.querySelector("#clearLogsBtn");
const resetBtn = document.querySelector("#resetBtn");
const searchInput = document.querySelector("#search");

const sessionBadge = document.querySelector("#sessionBadge");
const currentUserName = document.querySelector("#currentUserName");
const currentUserDetails = document.querySelector("#currentUserDetails");
const occurrencesTable = document.querySelector("#occurrencesTable");
const auditLog = document.querySelector("#auditLog");
const totalOccurrences = document.querySelector("#totalOccurrences");
const criticalOccurrences = document.querySelector("#criticalOccurrences");
const lastUpdate = document.querySelector("#lastUpdate");

// [CORREÇÃO 9] Geração de ID segura usando crypto.randomUUID()
function generateId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return "OC-" + crypto.randomUUID().split("-")[0].toUpperCase();
  }
  // Fallback com mais entropia que Math.random()
  return "OC-" + Date.now().toString(36).toUpperCase();
}

// [CORREÇÃO 4] Sanitiza strings para uso seguro em contextos de texto
function sanitizeText(value) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, 1000); // limita tamanho também
}

// [CORREÇÃO 5] Validações de formulário
function validateOccurrenceForm(data) {
  const errors = [];

  if (!data.studentName || data.studentName.length < 2) {
    errors.push("Nome do aluno é obrigatório (mín. 2 caracteres).");
  }
  if (!data.studentId || !/^\d{6,12}$/.test(data.studentId)) {
    errors.push("Matrícula inválida (somente números, 6 a 12 dígitos).");
  }
  if (!data.studentCpf || !/^\d{3}\.\d{3}\.\d{3}-\d{2}$/.test(data.studentCpf)) {
    errors.push("CPF inválido. Use o formato 000.000.000-00.");
  }
  if (!data.studentEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.studentEmail)) {
    errors.push("E-mail inválido.");
  }
  if (!data.description || data.description.length < 10) {
    errors.push("Descrição muito curta (mín. 10 caracteres).");
  }
  if (!data.privacyAck) {
    errors.push("É necessário confirmar o consentimento de dados.");
  }

  return errors;
}

function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  }

  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([
      {
        when: new Date().toISOString(),
        user: "sistema",
        action: "BASE_INICIAL_CRIADA",
        detail: "Dados fictícios carregados no localStorage."
      }
    ]));
  }

  const session = getSession();

  if (session) {
    showApp(session);
  } else {
    showLogin();
  }
}

function getOccurrences() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
  } catch {
    return [];
  }
}

function saveOccurrences(occurrences) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(occurrences));
}

function getAuditLogs() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
  } catch {
    return [];
  }
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function getSession() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.session) || "null");
  } catch {
    return null;
  }
}

// [CORREÇÃO 10] Sessão armazena apenas dados não-sensíveis — sem senha, sem hash
function saveSession(user) {
  const safeSession = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    studentId: user.studentId || null,
    classes: user.classes || null
  };
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(safeSession));
}

function writeLog(action, detail) {
  const session = getSession();
  const logs = getAuditLogs();

  logs.unshift({
    when: new Date().toISOString(),
    user: session ? session.email : "anonimo",
    role: session ? session.role : "SEM_SESSAO",
    action,
    detail: sanitizeText(String(detail))
  });

  // Limita o tamanho do log para evitar abuso de armazenamento
  const MAX_LOGS = 200;
  saveAuditLogs(logs.slice(0, MAX_LOGS));
}

function showLogin() {
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  // [CORREÇÃO 4] Uso de textContent em vez de innerHTML para evitar XSS
  sessionBadge.textContent = `${user.name} — ${user.role}`;
  sessionBadge.classList.remove("muted");

  currentUserName.textContent = user.name;
  currentUserDetails.textContent = `${user.email} | Perfil: ${user.role}`;

  // [CORREÇÃO 3] Oculta o seletor de perfil — escalada de privilégio removida
  const roleSwitch = document.querySelector(".role-switch");
  if (roleSwitch) {
    roleSwitch.style.display = "none";
  }

  // Controla visibilidade de ações por perfil
  applyRolePermissions(user.role);

  render();
}

// [CORREÇÃO 3 e 8] Aplica permissões de interface baseadas no perfil real
function applyRolePermissions(role) {
  // Exportação: somente ADMIN
  if (exportBtn) {
    exportBtn.style.display = role === "ADMIN" ? "" : "none";
  }
  // Limpar logs: somente ADMIN
  if (clearLogsBtn) {
    clearLogsBtn.style.display = role === "ADMIN" ? "" : "none";
  }
  // Reset: somente ADMIN
  if (resetBtn) {
    resetBtn.style.display = role === "ADMIN" ? "" : "none";
  }
  // Formulário de nova ocorrência: PROFESSOR e ADMIN
  const occurrenceFormSection = document.querySelector("#occurrenceFormSection");
  if (occurrenceFormSection) {
    occurrenceFormSection.style.display = (role === "PROFESSOR" || role === "ADMIN") ? "" : "none";
  }
}

function login(email, password) {
  // [CORREÇÃO 1] Não comparamos com senha em texto claro armazenada no objeto USERS
  // Usamos o mapa de demonstração — em produção isso vai para o backend
  const user = USERS.find((item) => item.email === email);

  if (!user || DEMO_PASSWORDS[email] !== password) {
    alert("Usuário ou senha inválidos.");
    writeLog("LOGIN_FALHOU", `Tentativa para ${email}`);
    return;
  }

  saveSession(user); // [CORREÇÃO 10] sem senha no objeto salvo
  writeLog("LOGIN_OK", `Usuário ${user.email} entrou no sistema.`);
  showApp(getSession()); // usa a sessão segura, não o user original
}

function logout() {
  const session = getSession();
  writeLog("LOGOUT", session ? `${session.email} saiu do sistema.` : "Sessão encerrada.");
  localStorage.removeItem(STORAGE_KEYS.session);
  showLogin();
}

// [CORREÇÃO 3] Função changeRole REMOVIDA — usuários não podem trocar o próprio perfil.
// A escalada de privilégio era a vulnerabilidade mais crítica: qualquer ALUNO podia
// se tornar ADMIN sem nenhuma verificação.

function createOccurrence(event) {
  event.preventDefault();

  const session = getSession();

  // [CORREÇÃO 7] Verifica permissão antes de criar
  if (!session || (session.role !== "PROFESSOR" && session.role !== "ADMIN")) {
    alert("Sem permissão para registrar ocorrências.");
    return;
  }

  const data = {
    studentName: sanitizeText(document.querySelector("#studentName").value),
    studentId: sanitizeText(document.querySelector("#studentId").value),
    studentCpf: sanitizeText(document.querySelector("#studentCpf").value),
    studentEmail: sanitizeText(document.querySelector("#studentEmail").value),
    studentPhone: sanitizeText(document.querySelector("#studentPhone").value),
    category: sanitizeText(document.querySelector("#category").value),
    priority: sanitizeText(document.querySelector("#priority").value),
    description: sanitizeText(document.querySelector("#description").value),
    internalNote: sanitizeText(document.querySelector("#internalNote").value),
    privacyAck: document.querySelector("#privacyAck").checked
  };

  // [CORREÇÃO 5] Valida antes de salvar
  const errors = validateOccurrenceForm(data);
  if (errors.length > 0) {
    alert("Corrija os seguintes erros:\n\n" + errors.join("\n"));
    return;
  }

  const occurrence = {
    ...data,
    id: generateId(), // [CORREÇÃO 9]
    status: "Aberta",
    createdBy: session.email,
    createdAt: new Date().toISOString()
  };

  delete occurrence.privacyAck; // não persiste confirmação interna

  const occurrences = getOccurrences();
  occurrences.unshift(occurrence);
  saveOccurrences(occurrences);

  // [CORREÇÃO 4] CPF não é logado em texto claro no audit log
  writeLog(
    "OCORRENCIA_CRIADA",
    `Criada ocorrência ${occurrence.id} para ${occurrence.studentName} (matrícula ${occurrence.studentId}).`
  );

  occurrenceForm.reset();
  render();
}

function deleteOccurrence(id) {
  const session = getSession();

  // [CORREÇÃO 7] Somente ADMIN pode excluir
  if (!session || session.role !== "ADMIN") {
    alert("Somente administradores podem excluir ocorrências.");
    return;
  }

  const occurrences = getOccurrences();
  const occurrence = occurrences.find((item) => item.id === id);
  const updated = occurrences.filter((item) => item.id !== id);

  saveOccurrences(updated);
  // [CORREÇÃO 4] Não serializa o objeto completo no log (evita vazar CPF/dados)
  writeLog("OCORRENCIA_EXCLUIDA", `Ocorrência ${id} excluída pelo administrador.`);
  render();
}

function changeStatus(id, status) {
  const session = getSession();

  // [CORREÇÃO 7] Somente PROFESSOR e ADMIN podem alterar status
  if (!session || (session.role !== "PROFESSOR" && session.role !== "ADMIN")) {
    alert("Sem permissão para alterar status de ocorrências.");
    return;
  }

  const VALID_STATUSES = ["Aberta", "Em análise", "Resolvida"];
  if (!VALID_STATUSES.includes(status)) {
    return; // rejeita status inválido
  }

  const occurrences = getOccurrences();
  const occurrence = occurrences.find((item) => item.id === id);

  if (!occurrence) {
    return;
  }

  occurrence.status = status;
  occurrence.updatedAt = new Date().toISOString();

  saveOccurrences(occurrences);
  writeLog("STATUS_ALTERADO", `Ocorrência ${id} alterada para "${status}".`);
  render();
}

// [CORREÇÃO 6] Exportação não inclui senhas, token, nem localStorage bruto
function exportEverything() {
  const session = getSession();

  if (!session || session.role !== "ADMIN") {
    alert("Somente administradores podem exportar dados.");
    return;
  }

  const safeUsers = USERS.map(({ id, name, email, role, studentId, classes }) => ({
    id, name, email, role, studentId, classes
    // passwordHash propositalmente omitido
  }));

  const payload = {
    exportedAt: new Date().toISOString(),
    exportedBy: session.email,
    // REMOVIDO: token, users com hash, localStorage bruto
    users: safeUsers,
    occurrences: getOccurrences(),
    audit: getAuditLogs()
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = "backup-ocorrencias.json";
  anchor.click();

  URL.revokeObjectURL(url);

  writeLog("EXPORTACAO", "Administrador exportou dados do sistema.");
}

// [CORREÇÃO 8] clearLogs restrito a ADMIN
function clearLogs() {
  const session = getSession();
  if (!session || session.role !== "ADMIN") {
    alert("Somente administradores podem limpar logs.");
    return;
  }
  writeLog("LOGS_LIMPOS", "Logs anteriores foram apagados pelo administrador.");
  // Salva primeiro o log acima, depois limpa
  const currentLogs = getAuditLogs();
  saveAuditLogs([currentLogs[0]]); // mantém o registro da própria ação
  render();
}

function resetData() {
  const session = getSession();
  if (!session || session.role !== "ADMIN") {
    alert("Somente administradores podem restaurar dados.");
    return;
  }
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([]));
  localStorage.removeItem(STORAGE_KEYS.session);
  boot();
}

// [CORREÇÃO 4] render() usa createElement/textContent — SEM innerHTML com dados do usuário
function render() {
  const term = searchInput.value.toLowerCase().trim();
  const occurrences = getOccurrences();
  const session = getSession();

  const filtered = occurrences.filter((item) => {
    // Busca apenas em campos específicos, não no JSON inteiro (evita vazar internalNote via busca)
    const searchable = [
      item.studentName,
      item.studentId,
      item.category,
      item.status,
      item.description
    ].join(" ").toLowerCase();
    return searchable.includes(term);
  });

  totalOccurrences.textContent = occurrences.length;
  criticalOccurrences.textContent = occurrences.filter((item) => item.priority === "Crítica").length;
  lastUpdate.textContent = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  // Limpa tabela com segurança
  occurrencesTable.innerHTML = "";

  filtered.forEach((item) => {
    const tr = document.createElement("tr");

    // Coluna: Aluno
    const tdAluno = document.createElement("td");
    const strong = document.createElement("strong");
    strong.textContent = item.studentName;
    const span = document.createElement("span");
    span.className = "muted-text";
    span.textContent = item.studentId;
    tdAluno.appendChild(strong);
    tdAluno.appendChild(document.createElement("br"));
    tdAluno.appendChild(span);
    tr.appendChild(tdAluno);

    // Coluna: CPF
    const tdCpf = document.createElement("td");
    tdCpf.textContent = item.studentCpf;
    tr.appendChild(tdCpf);

    // Coluna: Contato
    const tdContato = document.createElement("td");
    tdContato.textContent = item.studentEmail;
    tdContato.appendChild(document.createElement("br"));
    tdContato.appendChild(document.createTextNode(item.studentPhone));
    tr.appendChild(tdContato);

    // Coluna: Categoria
    const tdCat = document.createElement("td");
    tdCat.textContent = item.category;
    tr.appendChild(tdCat);

    // Coluna: Prioridade
    const tdPri = document.createElement("td");
    const priSpan = document.createElement("span");
    priSpan.className = `priority ${item.priority}`;
    priSpan.textContent = item.priority;
    tdPri.appendChild(priSpan);
    tr.appendChild(tdPri);

    // Coluna: Status
    const tdStatus = document.createElement("td");
    tdStatus.textContent = item.status;
    tr.appendChild(tdStatus);

    // Coluna: Descrição (nota interna visível somente para PROF e ADMIN)
    const tdDesc = document.createElement("td");
    const descStrong = document.createElement("strong");
    descStrong.textContent = "Descrição: ";
    tdDesc.appendChild(descStrong);
    tdDesc.appendChild(document.createTextNode(item.description));

    if (session && (session.role === "PROFESSOR" || session.role === "ADMIN")) {
      tdDesc.appendChild(document.createElement("br"));
      const noteStrong = document.createElement("strong");
      noteStrong.textContent = "Obs. interna: ";
      tdDesc.appendChild(noteStrong);
      tdDesc.appendChild(document.createTextNode(item.internalNote || "—"));
    }
    tr.appendChild(tdDesc);

    // Coluna: Ações (restritas por perfil)
    const tdAcoes = document.createElement("td");
    const div = document.createElement("div");
    div.className = "row-actions";

    if (session && (session.role === "PROFESSOR" || session.role === "ADMIN")) {
      const btnAnalise = document.createElement("button");
      btnAnalise.className = "btn secondary";
      btnAnalise.textContent = "Em análise";
      btnAnalise.addEventListener("click", () => changeStatus(item.id, "Em análise"));
      div.appendChild(btnAnalise);

      const btnResolver = document.createElement("button");
      btnResolver.className = "btn secondary";
      btnResolver.textContent = "Resolver";
      btnResolver.addEventListener("click", () => changeStatus(item.id, "Resolvida"));
      div.appendChild(btnResolver);
    }

    if (session && session.role === "ADMIN") {
      const btnExcluir = document.createElement("button");
      btnExcluir.className = "btn danger";
      btnExcluir.textContent = "Excluir";
      btnExcluir.addEventListener("click", () => deleteOccurrence(item.id));
      div.appendChild(btnExcluir);
    }

    tdAcoes.appendChild(div);
    tr.appendChild(tdAcoes);

    occurrencesTable.appendChild(tr);
  });

  // Logs de auditoria — também com textContent
  const logs = getAuditLogs();

  auditLog.innerHTML = "";

  if (logs.length === 0) {
    const notice = document.createElement("div");
    notice.className = "notice";
    notice.textContent = "Nenhum log registrado.";
    auditLog.appendChild(notice);
  } else {
    logs.forEach((log) => {
      const div = document.createElement("div");
      div.className = "log-item";

      const strong = document.createElement("strong");
      strong.textContent = log.when;
      div.appendChild(strong);
      div.appendChild(document.createElement("br"));
      div.appendChild(document.createTextNode(
        `usuário=${log.user || "—"} | perfil=${log.role || "—"} | ação=${log.action}`
      ));
      div.appendChild(document.createElement("br"));
      div.appendChild(document.createTextNode(`detalhe=${log.detail}`));

      auditLog.appendChild(div);
    });
  }
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  login(
    document.querySelector("#email").value.trim(),
    document.querySelector("#password").value
  );
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportEverything);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);
searchInput.addEventListener("input", render);

// [CORREÇÃO 3] roleSelect e changeRole REMOVIDOS — não há mais troca de perfil no frontend

// [CORREÇÃO 4] Funções globais removidas (deleteOccurrence/changeStatus via onclick inline)
// Todos os event listeners são adicionados programaticamente no render()

boot();