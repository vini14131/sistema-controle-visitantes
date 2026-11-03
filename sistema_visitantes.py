# -*- coding: utf-8 -*-
"""
Projeto Prático - Sistema de Controle de Visitantes
Desenvolvido para a disciplina de Segurança da Informação.

Aplicação desktop em Python utilizando Tkinter e SQLite.
Implementa autenticação, autorização baseada em perfis (RBAC),
criptografia de senhas (PBKDF2-SHA256 com Salt) e auditoria de ações.
"""

import hashlib
import hmac
import os
import re
import sqlite3
import sys
import tkinter as tk
import traceback
from contextlib import contextmanager
from datetime import datetime
from tkinter import messagebox, ttk

# Diretório base para arquivos locais (banco e log)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "visitantes.db")
LOG_PATH = os.path.join(BASE_DIR, "security.log")

# Perfis de acesso
ROLE_ADMIN = "admin"
ROLE_OPERADOR = "operador"
ROLES_VALIDAS = (ROLE_ADMIN, ROLE_OPERADOR)
ROLE_ROTULOS = {ROLE_ADMIN: "Administrador", ROLE_OPERADOR: "Operador"}

# Usuário administrador padrão para a primeira inicialização
ADMIN_PADRAO_USUARIO = "admin"
ADMIN_PADRAO_SENHA = "admin123"

# Parâmetros de hash de senha
PBKDF2_ALGORITMO = "pbkdf2_sha256"
PBKDF2_ITERACOES = 260_000
SALT_BYTES = 16

# Limites de entrada
TAMANHO_MIN_SENHA = 6
TAMANHO_MAX_LOGIN = 40
TAMANHO_MAX_TEXTO = 120

# Constantes de log de auditoria
ACAO_LOGIN_OK = "LOGIN_OK"
ACAO_LOGIN_FALHA = "LOGIN_FALHA"
ACAO_ACESSO_NEGADO = "ACESSO_NEGADO"
ACAO_CADASTRO_USUARIO = "CADASTRO_USUARIO"
ACAO_CADASTRO_VISITANTE = "CADASTRO_VISITANTE"
ACAO_LOGOUT = "LOGOUT"
ACAO_INICIALIZACAO = "INICIALIZACAO"
ACAO_ERRO_INTERNO = "ERRO_INTERNO"

FORMATO_DATA_HORA = "%Y-%m-%d %H:%M:%S"

PADRAO_LINHA_LOG = re.compile(
    r"^\[(?P<quando>[^\]]*)\]\s*\[(?P<usuario>[^\]]*)\]\s*"
    r"\[(?P<acao>[^\]]*)\]\s*(?P<detalhe>.*)$"
)


# ---------------------------------------------------------------------------
# SEGURANÇA E UTILITÁRIOS
# ---------------------------------------------------------------------------

def gerar_hash_senha(senha, salt=None):
    """Gera o hash PBKDF2 com SHA-256 e salt para o banco de dados."""
    if not isinstance(senha, str) or not senha:
        raise ValueError("A senha deve ser um texto não vazio.")

    if salt is None:
        salt = os.urandom(SALT_BYTES)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    derivado = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt, PBKDF2_ITERACOES
    )
    return "{}${}${}${}".format(
        PBKDF2_ALGORITMO, PBKDF2_ITERACOES, salt.hex(), derivado.hex()
    )


def verificar_senha(senha, senha_armazenada):
    """Compara a senha informada com o hash salvo no banco."""
    if not senha or not senha_armazenada:
        return False

    try:
        algoritmo, iteracoes, salt_hex, hash_hex = senha_armazenada.split("$")
        if algoritmo != PBKDF2_ALGORITMO:
            return False
        iteracoes = int(iteracoes)
        if iteracoes <= 0:
            return False
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError, TypeError):
        return False

    try:
        calculado = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), salt, iteracoes
        )
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(calculado.hex(), hash_hex)


def _sanitizar_campo_log(valor):
    """Sanitiza o texto para prevenir injeções no arquivo de log."""
    texto = "-" if valor is None else str(valor)
    texto = texto.replace("\r", " ").replace("\n", " ")
    texto = texto.replace("[", "(").replace("]", ")")
    return texto.strip() or "-"


def registrar_log(usuario, acao, detalhe=""):
    """Grava o registro de auditoria no arquivo security.log."""
    quando = datetime.now().strftime(FORMATO_DATA_HORA)
    linha = "[{}] [{}] [{}] {}".format(
        quando,
        _sanitizar_campo_log(usuario),
        _sanitizar_campo_log(acao),
        _sanitizar_campo_log(detalhe),
    )
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as arquivo:
            arquivo.write(linha + "\n")
    except OSError as erro:
        print(
            "[AVISO] Não foi possível gravar em {}: {}".format(LOG_PATH, erro),
            file=sys.stderr,
        )


def ler_logs(limite=2000):
    """Lê as últimas linhas do arquivo de auditoria."""
    if not os.path.exists(LOG_PATH):
        return []

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as arquivo:
            linhas = arquivo.readlines()
    except OSError as erro:
        raise RuntimeError("Não foi possível ler o arquivo de log: {}".format(erro))

    registros = []
    for linha in linhas[-limite:]:
        linha = linha.rstrip("\n")
        if not linha.strip():
            continue
        casamento = PADRAO_LINHA_LOG.match(linha)
        if casamento:
            registros.append(casamento.groupdict())
        else:
            registros.append(
                {"quando": "-", "usuario": "-", "acao": "DESCONHECIDO", "detalhe": linha}
            )

    registros.reverse()
    return registros


# ---------------------------------------------------------------------------
# CAMADA DE PERSISTÊNCIA (SQLITE)
# ---------------------------------------------------------------------------

@contextmanager
def conexao_db():
    """Gerenciador de contexto para conexões com o SQLite."""
    conexao = sqlite3.connect(DB_PATH)
    conexao.row_factory = sqlite3.Row
    try:
        yield conexao
        conexao.commit()
    except Exception:
        conexao.rollback()
        raise
    finally:
        conexao.close()


def setup_database():
    """Inicializa as tabelas do banco de dados e cria o admin inicial se vazio."""
    coluna_adicionada = None
    with conexao_db() as conexao:
        conexao.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL CHECK (role IN ('admin', 'operador'))
            )
            """
        )
        conexao.execute(
            """
            CREATE TABLE IF NOT EXISTS visitantes (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                nome           TEXT    NOT NULL,
                documento      TEXT    NOT NULL,
                data_registro  TEXT    NOT NULL,
                registrado_por TEXT
            )
            """
        )

        colunas_visitantes = {
            linha["name"]
            for linha in conexao.execute("PRAGMA table_info(visitantes)").fetchall()
        }
        if "registrado_por" not in colunas_visitantes:
            conexao.execute("ALTER TABLE visitantes ADD COLUMN registrado_por TEXT")
            coluna_adicionada = "registrado_por"

        total_usuarios = conexao.execute(
            "SELECT COUNT(*) AS total FROM usuarios"
        ).fetchone()["total"]

        if total_usuarios == 0:
            conexao.execute(
                "INSERT INTO usuarios (username, password_hash, role) VALUES (?, ?, ?)",
                (
                    ADMIN_PADRAO_USUARIO,
                    gerar_hash_senha(ADMIN_PADRAO_SENHA),
                    ROLE_ADMIN,
                ),
            )
            criou_padrao = True
        else:
            criou_padrao = False

    if criou_padrao:
        registrar_log(
            "sistema",
            ACAO_INICIALIZACAO,
            "banco criado; usuário padrão '{}' (perfil admin) inserido".format(
                ADMIN_PADRAO_USUARIO
            ),
        )
    if coluna_adicionada:
        registrar_log(
            "sistema",
            ACAO_INICIALIZACAO,
            "migração aplicada: coluna visitantes.{} criada".format(coluna_adicionada),
        )
    return criou_padrao


# ---------------------------------------------------------------------------
# REGRAS DE NEGÓCIO E CONTROLE DE ACESSO
# ---------------------------------------------------------------------------

class AcessoNegado(Exception):
    """Exceção para operações não permitidas pelo perfil do usuário."""


def exigir_admin(usuario_sessao, operacao):
    """Garante permissão de administrador para a operação."""
    if usuario_sessao and usuario_sessao.get("role") == ROLE_ADMIN:
        return True

    nome = usuario_sessao.get("username") if usuario_sessao else "sem-sessao"
    perfil = usuario_sessao.get("role") if usuario_sessao else "nenhum"
    registrar_log(
        nome,
        ACAO_ACESSO_NEGADO,
        "operação '{}' negada para o perfil '{}'".format(operacao, perfil),
    )
    raise AcessoNegado(
        "Acesso Negado: a operação \"{}\" é restrita ao perfil Administrador.".format(
            operacao
        )
    )


def exigir_sessao(usuario_sessao, operacao):
    """Garante que o usuário esteja autenticado."""
    if not usuario_sessao:
        registrar_log("sem-sessao", ACAO_ACESSO_NEGADO,
                      "operação '{}' sem autenticação".format(operacao))
        raise AcessoNegado("Acesso Negado: é necessário estar autenticado.")


def validar_texto_obrigatorio(valor, nome_campo, tamanho_max=TAMANHO_MAX_TEXTO):
    """Valida obrigatoriedade e extensão do texto digitado."""
    texto = "" if valor is None else str(valor).strip()
    if not texto:
        raise ValueError("Preencha todos os campos. O campo \"{}\" está vazio.".format(nome_campo))
    if len(texto) > tamanho_max:
        raise ValueError(
            "O campo \"{}\" deve ter no máximo {} caracteres.".format(nome_campo, tamanho_max)
        )
    if any(caractere in texto for caractere in ("\r", "\n", "\x00")):
        raise ValueError("O campo \"{}\" contém caracteres inválidos.".format(nome_campo))
    return texto


def validar_login(username):
    texto = validar_texto_obrigatorio(username, "Usuário", TAMANHO_MAX_LOGIN)
    if " " in texto:
        raise ValueError("O usuário não pode conter espaços.")
    return texto


def validar_senha(senha, confirmacao=None):
    if not senha:
        raise ValueError("Preencha todos os campos. O campo \"Senha\" está vazio.")
    if len(senha) < TAMANHO_MIN_SENHA:
        raise ValueError(
            "A senha deve ter no mínimo {} caracteres.".format(TAMANHO_MIN_SENHA)
        )
    if confirmacao is not None and senha != confirmacao:
        raise ValueError("A confirmação da senha não confere.")
    return senha


def autenticar(username, senha):
    """Autentica o usuário e retorna o dicionário da sessão."""
    username = (username or "").strip()
    if not username or not senha:
        raise ValueError("Preencha todos os campos.")

    try:
        with conexao_db() as conexao:
            linha = conexao.execute(
                "SELECT id, username, password_hash, role FROM usuarios WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error as erro:
        raise RuntimeError("Falha ao consultar o banco de dados: {}".format(erro))

    if linha is None or not verificar_senha(senha, linha["password_hash"]):
        registrar_log(username, ACAO_LOGIN_FALHA, "usuário ou senha inválidos")
        return None

    sessao = {"id": linha["id"], "username": linha["username"], "role": linha["role"]}
    registrar_log(sessao["username"], ACAO_LOGIN_OK, "perfil={}".format(sessao["role"]))
    return sessao


def encerrar_sessao(usuario_sessao):
    if usuario_sessao:
        registrar_log(usuario_sessao["username"], ACAO_LOGOUT, "sessão finalizada")


def cadastrar_usuario(usuario_sessao, username, senha, confirmacao, role):
    """Cadastra um novo usuário (exclusivo para Admin)."""
    exigir_admin(usuario_sessao, "cadastro de usuários")

    username = validar_login(username)
    senha = validar_senha(senha, confirmacao)

    if role not in ROLES_VALIDAS:
        raise ValueError("Perfil inválido. Selecione Administrador ou Operador.")

    try:
        with conexao_db() as conexao:
            conexao.execute(
                "INSERT INTO usuarios (username, password_hash, role) VALUES (?, ?, ?)",
                (username, gerar_hash_senha(senha), role),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Já existe um usuário cadastrado com o login \"{}\".".format(username))
    except sqlite3.Error as erro:
        raise RuntimeError("Falha ao gravar o usuário no banco de dados: {}".format(erro))

    registrar_log(
        usuario_sessao["username"],
        ACAO_CADASTRO_USUARIO,
        "novo usuário '{}' com perfil '{}'".format(username, role),
    )
    return username


def cadastrar_visitante(usuario_sessao, nome, documento):
    """Cadastra um visitante atrelando ao usuário logado."""
    exigir_sessao(usuario_sessao, "cadastro de visitantes")

    nome = validar_texto_obrigatorio(nome, "Nome")
    documento = validar_texto_obrigatorio(documento, "Documento")
    quando = datetime.now().strftime(FORMATO_DATA_HORA)

    registrado_por = usuario_sessao["username"]

    try:
        with conexao_db() as conexao:
            cursor = conexao.execute(
                "INSERT INTO visitantes (nome, documento, data_registro, registrado_por) "
                "VALUES (?, ?, ?, ?)",
                (nome, documento, quando, registrado_por),
            )
            novo_id = cursor.lastrowid
    except sqlite3.Error as erro:
        raise RuntimeError("Falha ao gravar o visitante no banco de dados: {}".format(erro))

    registrar_log(
        registrado_por,
        ACAO_CADASTRO_VISITANTE,
        "id={} nome='{}' documento='{}'".format(novo_id, nome, documento),
    )
    return novo_id


def listar_visitantes(usuario_sessao):
    """Retorna os visitantes cadastrados em ordem decrescente."""
    exigir_sessao(usuario_sessao, "consulta de visitantes")

    try:
        with conexao_db() as conexao:
            linhas = conexao.execute(
                "SELECT id, nome, documento, data_registro, registrado_por "
                "FROM visitantes ORDER BY id DESC"
            ).fetchall()
    except sqlite3.Error as erro:
        raise RuntimeError("Falha ao consultar os visitantes: {}".format(erro))

    return [dict(linha) for linha in linhas]


def obter_logs(usuario_sessao, limite=2000):
    exigir_admin(usuario_sessao, "visualização dos logs de segurança")
    return ler_logs(limite=limite)


# ---------------------------------------------------------------------------
# INTERFACE GRÁFICA (TKINTER)
# ---------------------------------------------------------------------------

def criar_treeview(pai, colunas):
    """Cria componente Treeview com barra de rolagem."""
    container = ttk.Frame(pai)
    container.rowconfigure(0, weight=1)
    container.columnconfigure(0, weight=1)

    tree = ttk.Treeview(
        container,
        columns=[coluna[0] for coluna in colunas],
        show="headings",
        selectmode="browse",
    )
    for chave, titulo, largura, alinhamento in colunas:
        tree.heading(chave, text=titulo)
        tree.column(chave, width=largura, anchor=alinhamento, stretch=(chave == colunas[-1][0]))
    tree.tag_configure("par", background="#f2f5f9")

    barra = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=barra.set)

    tree.grid(row=0, column=0, sticky="nsew")
    barra.grid(row=0, column=1, sticky="ns")
    return container, tree


class DialogoBase(tk.Toplevel):
    """Classe base para janelas modais da aplicação."""

    def __init__(self, master, titulo):
        super().__init__(master)
        self.title(titulo)
        self.transient(master.winfo_toplevel())
        self.protocol("WM_DELETE_WINDOW", self.fechar)
        self.bind("<Escape>", lambda evento: self.fechar())

    def fechar(self):
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()

    def exibir(self):
        self.update_idletasks()
        principal = self.master.winfo_toplevel()
        largura = self.winfo_width()
        altura = self.winfo_height()
        x = principal.winfo_rootx() + max((principal.winfo_width() - largura) // 2, 0)
        y = principal.winfo_rooty() + max((principal.winfo_height() - altura) // 2, 0)
        self.geometry("+{}+{}".format(x, y))
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.focus_set()


class TelaLogin(ttk.Frame):
    """Tela de autenticação inicial."""

    def __init__(self, master, app):
        super().__init__(master, padding=20)
        self.app = app
        self.var_usuario = tk.StringVar()
        self.var_senha = tk.StringVar()
        self._construir()

    def _construir(self):
        cartao = ttk.Frame(self)
        cartao.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(cartao, text="Controle de Visitantes", style="Titulo.TLabel").grid(
            row=0, column=0, columnspan=2, pady=(0, 4)
        )
        ttk.Label(
            cartao,
            text="Acesso restrito a usuários autorizados",
            style="Sub.TLabel",
        ).grid(row=1, column=0, columnspan=2, pady=(0, 20))

        ttk.Label(cartao, text="Usuário:").grid(row=2, column=0, sticky="e", padx=(0, 10), pady=6)
        self.entry_usuario = ttk.Entry(cartao, textvariable=self.var_usuario, width=30)
        self.entry_usuario.grid(row=2, column=1, pady=6, sticky="we")

        ttk.Label(cartao, text="Senha:").grid(row=3, column=0, sticky="e", padx=(0, 10), pady=6)
        self.entry_senha = ttk.Entry(cartao, textvariable=self.var_senha, width=30, show="*")
        self.entry_senha.grid(row=3, column=1, pady=6, sticky="we")

        botoes = ttk.Frame(cartao)
        botoes.grid(row=4, column=0, columnspan=2, pady=(18, 0), sticky="we")
        botoes.columnconfigure(0, weight=1)
        botoes.columnconfigure(1, weight=1)

        ttk.Button(botoes, text="Entrar", style="Acao.TButton", command=self._entrar).grid(
            row=0, column=0, sticky="we", padx=(0, 5)
        )
        ttk.Button(botoes, text="Sair", command=self._cancelar).grid(
            row=0, column=1, sticky="we", padx=(5, 0)
        )

        self.entry_usuario.bind("<Return>", self._entrar)
        self.entry_senha.bind("<Return>", self._entrar)
        self.after(50, self.entry_usuario.focus_set)

    def _entrar(self, evento=None):
        usuario = self.var_usuario.get().strip()
        senha = self.var_senha.get()

        if not usuario or not senha:
            messagebox.showwarning(
                "Campos obrigatórios", "Preencha todos os campos.", parent=self
            )
            return

        try:
            sessao = autenticar(usuario, senha)
        except ValueError as erro:
            messagebox.showwarning("Validação", str(erro), parent=self)
            return
        except RuntimeError as erro:
            messagebox.showerror("Erro de banco de dados", str(erro), parent=self)
            return

        if sessao is None:
            self.var_senha.set("")
            self.entry_senha.focus_set()
            messagebox.showerror(
                "Credenciais incorretas",
                "Usuário ou senha inválidos.\nVerifique os dados e tente novamente.",
                parent=self,
            )
            return

        self.app.iniciar_sessao(sessao)

    def _cancelar(self):
        self.app.encerrar_aplicacao()


class TelaPrincipal(ttk.Frame):
    """Painel principal do sistema."""

    def __init__(self, master, app):
        super().__init__(master, padding=18)
        self.app = app
        self.usuario = app.usuario_logado
        if not self.usuario:
            raise AcessoNegado("Acesso Negado: é necessário estar autenticado.")
        self._construir()

    def _eh_admin(self):
        return self.usuario.get("role") == ROLE_ADMIN

    def _construir(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        cabecalho = ttk.Frame(self)
        cabecalho.grid(row=0, column=0, sticky="we")
        cabecalho.columnconfigure(0, weight=1)

        ttk.Label(cabecalho, text="Painel Principal", style="Titulo.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            cabecalho,
            text="Usuário: {}   |   Perfil: {}".format(
                self.usuario["username"], ROLE_ROTULOS.get(self.usuario["role"], self.usuario["role"])
            ),
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        ttk.Button(cabecalho, text="Sair (Logout)", command=self._logout).grid(
            row=0, column=1, rowspan=2, sticky="e"
        )

        painel = ttk.LabelFrame(self, text="Ações disponíveis", padding=18)
        painel.grid(row=1, column=0, sticky="nsew", pady=14)
        painel.columnconfigure(0, weight=1)

        linha = 0

        ttk.Button(
            painel,
            text="Cadastrar Visitante",
            style="Acao.TButton",
            command=self._abrir_cadastro_visitante,
        ).grid(row=linha, column=0, sticky="we", pady=4)
        linha += 1

        ttk.Button(
            painel,
            text="Ver Visitantes",
            style="Acao.TButton",
            command=self._abrir_lista_visitantes,
        ).grid(row=linha, column=0, sticky="we", pady=4)
        linha += 1

        if self._eh_admin():
            ttk.Separator(painel, orient="horizontal").grid(
                row=linha, column=0, sticky="we", pady=12
            )
            linha += 1

            ttk.Label(painel, text="Administração (restrito ao perfil Admin)",
                      style="Sub.TLabel").grid(row=linha, column=0, sticky="w")
            linha += 1

            ttk.Button(
                painel,
                text="Cadastrar Novo Usuário (Admin/Operador)",
                style="Acao.TButton",
                command=self._abrir_cadastro_usuario,
            ).grid(row=linha, column=0, sticky="we", pady=4)
            linha += 1

            ttk.Button(
                painel,
                text="Ver Logs",
                style="Acao.TButton",
                command=self._abrir_logs,
            ).grid(row=linha, column=0, sticky="we", pady=4)
            linha += 1
        else:
            ttk.Label(
                painel,
                text="Perfil Operador: apenas cadastro e consulta de visitantes.\n"
                     "As funcionalidades administrativas não estão disponíveis.",
                style="Sub.TLabel",
                justify="left",
            ).grid(row=linha, column=0, sticky="w", pady=(16, 0))

    def _confirmar_admin(self, operacao):
        try:
            exigir_admin(self.usuario, operacao)
            return True
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
            return False

    def _abrir_cadastro_visitante(self):
        try:
            DialogoCadastroVisitante(self, self.app, self.usuario).exibir()
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)

    def _abrir_lista_visitantes(self):
        try:
            DialogoListaVisitantes(self, self.app, self.usuario).exibir()
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
        except RuntimeError as erro:
            messagebox.showerror("Erro", str(erro), parent=self)

    def _abrir_cadastro_usuario(self):
        if not self._confirmar_admin("cadastro de usuários"):
            return
        DialogoCadastroUsuario(self, self.app, self.usuario).exibir()

    def _abrir_logs(self):
        if not self._confirmar_admin("visualização dos logs de segurança"):
            return
        try:
            DialogoLogs(self, self.app, self.usuario).exibir()
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
        except RuntimeError as erro:
            messagebox.showerror("Erro", str(erro), parent=self)

    def _logout(self):
        self.app.encerrar_sessao()


class DialogoCadastroVisitante(DialogoBase):
    """Janela modal para cadastro de visitantes."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Cadastrar Visitante")
        self.app = app
        self.usuario = usuario
        self.var_nome = tk.StringVar()
        self.var_documento = tk.StringVar()
        self._construir()

    def _construir(self):
        corpo = ttk.Frame(self, padding=18)
        corpo.pack(fill="both", expand=True)

        ttk.Label(corpo, text="Nome completo:").grid(row=0, column=0, sticky="e", padx=(0, 10), pady=6)
        entry_nome = ttk.Entry(corpo, textvariable=self.var_nome, width=36)
        entry_nome.grid(row=0, column=1, pady=6, sticky="we")

        ttk.Label(corpo, text="Documento (RG/CPF):").grid(row=1, column=0, sticky="e", padx=(0, 10), pady=6)
        entry_documento = ttk.Entry(corpo, textvariable=self.var_documento, width=36)
        entry_documento.grid(row=1, column=1, pady=6, sticky="we")

        botoes = ttk.Frame(corpo)
        botoes.grid(row=2, column=0, columnspan=2, pady=(16, 0), sticky="we")
        botoes.columnconfigure(0, weight=1)
        botoes.columnconfigure(1, weight=1)

        ttk.Button(botoes, text="Salvar", style="Acao.TButton", command=self._salvar).grid(
            row=0, column=0, sticky="we", padx=(0, 5)
        )
        ttk.Button(botoes, text="Cancelar", command=self.fechar).grid(
            row=0, column=1, sticky="we", padx=(5, 0)
        )

        entry_nome.bind("<Return>", lambda evento: entry_documento.focus_set())
        entry_documento.bind("<Return>", self._salvar)
        self.after(50, entry_nome.focus_set)

    def _salvar(self, evento=None):
        try:
            novo_id = cadastrar_visitante(
                self.usuario, self.var_nome.get(), self.var_documento.get()
            )
        except ValueError as erro:
            messagebox.showwarning("Validação", str(erro), parent=self)
            return
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
            return
        except RuntimeError as erro:
            messagebox.showerror("Erro de banco de dados", str(erro), parent=self)
            return

        messagebox.showinfo(
            "Sucesso",
            "Visitante cadastrado com sucesso (registro nº {}).".format(novo_id),
            parent=self,
        )
        self.fechar()


class DialogoCadastroUsuario(DialogoBase):
    """Janela modal para cadastro de usuários (Admin apenas)."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Cadastrar Novo Usuário")
        self.app = app
        self.usuario = usuario
        self.var_username = tk.StringVar()
        self.var_senha = tk.StringVar()
        self.var_confirmacao = tk.StringVar()
        self.var_perfil = tk.StringVar(value=ROLE_ROTULOS[ROLE_OPERADOR])
        self._construir()

    def _construir(self):
        corpo = ttk.Frame(self, padding=18)
        corpo.pack(fill="both", expand=True)

        campos = [
            ("Usuário (login):", self.var_username, False),
            ("Senha:", self.var_senha, True),
            ("Confirmar senha:", self.var_confirmacao, True),
        ]
        entradas = []
        for indice, (rotulo, variavel, oculto) in enumerate(campos):
            ttk.Label(corpo, text=rotulo).grid(row=indice, column=0, sticky="e", padx=(0, 10), pady=6)
            entrada = ttk.Entry(
                corpo,
                textvariable=variavel,
                width=32,
                show="*" if oculto else "",
            )
            entrada.grid(row=indice, column=1, pady=6, sticky="we")
            entradas.append(entrada)

        ttk.Label(corpo, text="Perfil:").grid(row=3, column=0, sticky="e", padx=(0, 10), pady=6)
        seletor = ttk.Combobox(
            corpo,
            textvariable=self.var_perfil,
            state="readonly",
            values=(ROLE_ROTULOS[ROLE_ADMIN], ROLE_ROTULOS[ROLE_OPERADOR]),
            width=30,
        )
        seletor.grid(row=3, column=1, pady=6, sticky="we")

        ttk.Label(
            corpo,
            text="A senha é gravada apenas em formato hash (PBKDF2-SHA256).",
            style="Sub.TLabel",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        botoes = ttk.Frame(corpo)
        botoes.grid(row=5, column=0, columnspan=2, pady=(16, 0), sticky="we")
        botoes.columnconfigure(0, weight=1)
        botoes.columnconfigure(1, weight=1)

        ttk.Button(botoes, text="Salvar", style="Acao.TButton", command=self._salvar).grid(
            row=0, column=0, sticky="we", padx=(0, 5)
        )
        ttk.Button(botoes, text="Cancelar", command=self.fechar).grid(
            row=0, column=1, sticky="we", padx=(5, 0)
        )

        entradas[2].bind("<Return>", self._salvar)
        self.after(50, entradas[0].focus_set)

    def _salvar(self, evento=None):
        rotulo = self.var_perfil.get()
        perfil = next(
            (chave for chave, valor in ROLE_ROTULOS.items() if valor == rotulo), None
        )

        try:
            cadastrar_usuario(
                self.usuario,
                self.var_username.get(),
                self.var_senha.get(),
                self.var_confirmacao.get(),
                perfil,
            )
        except ValueError as erro:
            messagebox.showwarning("Validação", str(erro), parent=self)
            return
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
            return
        except RuntimeError as erro:
            messagebox.showerror("Erro de banco de dados", str(erro), parent=self)
            return

        messagebox.showinfo(
            "Sucesso",
            "Usuário \"{}\" cadastrado com o perfil {}.".format(
                self.var_username.get().strip(), rotulo
            ),
            parent=self,
        )
        self.fechar()


class DialogoListaVisitantes(DialogoBase):
    """Janela modal para listagem de visitantes."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Visitantes Cadastrados")
        self.app = app
        self.usuario = usuario
        self._construir()
        self._carregar()

    def _construir(self):
        self.geometry("900x430")
        corpo = ttk.Frame(self, padding=14)
        corpo.pack(fill="both", expand=True)
        corpo.rowconfigure(0, weight=1)
        corpo.columnconfigure(0, weight=1)

        colunas = [
            ("id", "Nº", 60, "center"),
            ("nome", "Nome", 240, "w"),
            ("documento", "Documento", 150, "w"),
            ("data_registro", "Data do Registro", 150, "w"),
            ("registrado_por", "Registrado por", 150, "w"),
        ]
        container, self.tree = criar_treeview(corpo, colunas)
        container.grid(row=0, column=0, sticky="nsew")

        rodape = ttk.Frame(corpo)
        rodape.grid(row=1, column=0, sticky="we", pady=(12, 0))
        rodape.columnconfigure(0, weight=1)
        self.var_total = tk.StringVar(value="Total de visitantes: 0")
        ttk.Label(rodape, textvariable=self.var_total, style="Sub.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(rodape, text="Atualizar", command=self._carregar).grid(row=0, column=1, padx=5)
        ttk.Button(rodape, text="Fechar", command=self.fechar).grid(row=0, column=2)

    def _carregar(self):
        try:
            visitantes = listar_visitantes(self.usuario)
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
            self.fechar()
            return
        except RuntimeError as erro:
            messagebox.showerror("Erro de banco de dados", str(erro), parent=self)
            return

        self.tree.delete(*self.tree.get_children())
        for indice, visitante in enumerate(visitantes):
            self.tree.insert(
                "",
                "end",
                values=(
                    visitante["id"],
                    visitante["nome"],
                    visitante["documento"],
                    visitante["data_registro"],
                    visitante.get("registrado_por") or "- não informado -",
                ),
                tags=("par",) if indice % 2 else (),
            )
        self.var_total.set("Total de visitantes: {}".format(len(visitantes)))


class DialogoLogs(DialogoBase):
    """Janela modal para exibição dos logs de auditoria."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Logs de Segurança")
        self.app = app
        self.usuario = usuario
        self._construir()
        self._carregar()

    def _construir(self):
        self.geometry("900x480")
        corpo = ttk.Frame(self, padding=14)
        corpo.pack(fill="both", expand=True)
        corpo.rowconfigure(0, weight=1)
        corpo.columnconfigure(0, weight=1)

        colunas = [
            ("quando", "Data/Hora", 160, "w"),
            ("usuario", "Usuário", 130, "w"),
            ("acao", "Ação", 150, "w"),
            ("detalhe", "Detalhe", 420, "w"),
        ]
        container, self.tree = criar_treeview(corpo, colunas)
        container.grid(row=0, column=0, sticky="nsew")

        rodape = ttk.Frame(corpo)
        rodape.grid(row=1, column=0, sticky="we", pady=(12, 0))
        rodape.columnconfigure(0, weight=1)
        self.var_total = tk.StringVar(value="Registros exibidos: 0")
        ttk.Label(rodape, textvariable=self.var_total, style="Sub.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(rodape, text="Arquivo: {}".format(LOG_PATH), style="Sub.TLabel").grid(
            row=1, column=0, sticky="w"
        )
        ttk.Button(rodape, text="Atualizar", command=self._carregar).grid(
            row=0, column=1, rowspan=2, padx=5
        )
        ttk.Button(rodape, text="Fechar", command=self.fechar).grid(
            row=0, column=2, rowspan=2
        )

    def _carregar(self):
        try:
            registros = obter_logs(self.usuario)
        except AcessoNegado as erro:
            messagebox.showerror("Acesso Negado", str(erro), parent=self)
            self.fechar()
            return
        except RuntimeError as erro:
            messagebox.showerror("Erro", str(erro), parent=self)
            return

        self.tree.delete(*self.tree.get_children())
        for indice, registro in enumerate(registros):
            self.tree.insert(
                "",
                "end",
                values=(
                    registro["quando"],
                    registro["usuario"],
                    registro["acao"],
                    registro["detalhe"],
                ),
                tags=("par",) if indice % 2 else (),
            )
        self.var_total.set("Registros exibidos: {}".format(len(registros)))


class AplicacaoVisitantes(tk.Tk):
    """Classe principal da aplicação."""

    def __init__(self):
        super().__init__()
        self.title("Sistema de Controle de Visitantes")
        self.geometry("900x580")
        self.minsize(780, 520)

        self.usuario_logado = None
        self.tela_atual = None

        self._configurar_estilo()

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.report_callback_exception = self._tratar_excecao_tk

        self.mostrar_login()

    def _configurar_estilo(self):
        estilo = ttk.Style(self)
        try:
            estilo.theme_use("clam")
        except tk.TclError:
            pass

        estilo.configure("Titulo.TLabel", font=("Segoe UI", 16, "bold"))
        estilo.configure("Sub.TLabel", font=("Segoe UI", 9), foreground="#444444")
        estilo.configure("TLabel", font=("Segoe UI", 10))
        estilo.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
        estilo.configure("Acao.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 10))
        estilo.configure("Treeview", font=("Segoe UI", 10), rowheight=24)
        estilo.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _trocar_tela(self, classe_tela):
        if self.tela_atual is not None:
            self.tela_atual.destroy()
            self.tela_atual = None

        for filho in self.container.winfo_children():
            filho.destroy()

        try:
            self.tela_atual = classe_tela(self.container, self)
        except AcessoNegado as erro:
            self.usuario_logado = None
            for filho in self.container.winfo_children():
                filho.destroy()
            self.tela_atual = TelaLogin(self.container, self)
            messagebox.showerror("Acesso Negado", str(erro), parent=self.tela_atual)
        self.tela_atual.pack(fill="both", expand=True)

    def mostrar_login(self):
        self.usuario_logado = None
        self._trocar_tela(TelaLogin)

    def mostrar_tela_principal(self):
        if not self.usuario_logado:
            self.mostrar_login()
            return
        self._trocar_tela(TelaPrincipal)

    def iniciar_sessao(self, sessao):
        self.usuario_logado = dict(sessao)
        self.after_idle(self.mostrar_tela_principal)

    def encerrar_sessao(self):
        encerrar_sessao(self.usuario_logado)
        self.after_idle(self.mostrar_login)

    def encerrar_aplicacao(self):
        encerrar_sessao(self.usuario_logado)
        self.destroy()

    def _tratar_excecao_tk(self, tipo, valor, traceback_obj):
        detalhe = "".join(traceback.format_exception(tipo, valor, traceback_obj))
        print(detalhe, file=sys.stderr)
        registrar_log(
            self.usuario_logado["username"] if self.usuario_logado else "sistema",
            ACAO_ERRO_INTERNO,
            "{}: {}".format(getattr(tipo, "__name__", tipo), valor),
        )
        try:
            messagebox.showerror(
                "Erro inesperado",
                "Ocorreu um erro inesperado:\n\n{}\n\n"
                "A operação foi abortada e o erro foi registrado em security.log.".format(valor),
            )
        except tk.TclError:
            pass


# ---------------------------------------------------------------------------
# PONTO DE ENTRADA DA APLICAÇÃO
# ---------------------------------------------------------------------------

def main():
    try:
        setup_database()
    except (sqlite3.Error, OSError, ValueError) as erro:
        raiz = tk.Tk()
        raiz.withdraw()
        messagebox.showerror(
            "Erro de inicialização",
            "Não foi possível preparar o banco de dados:\n\n{}\n\n"
            "Verifique as permissões da pasta {}.".format(erro, BASE_DIR),
        )
        raiz.destroy()
        return 1

    try:
        app = AplicacaoVisitantes()
    except tk.TclError as erro:
        print("[ERRO] Não foi possível iniciar a interface gráfica: {}".format(erro),
              file=sys.stderr)
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
