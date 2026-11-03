# -*- coding: utf-8 -*-
"""
Projeto Prático - Sistema de Controle de Visitantes
Desenvolvido para a disciplina de Segurança da Informação.

Aplicação desktop em Python utilizando Tkinter e SQLite.
Implementa autenticação, autorização por perfil (RBAC),
armazenamento seguro de senhas (PBKDF2-SHA256) e auditoria de ações.
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

# Caminhos dos arquivos locais
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "visitantes.db")
LOG_PATH = os.path.join(BASE_DIR, "security.log")

# Perfis de acesso (RBAC)
ROLE_ADMIN = "admin"
ROLE_OPERADOR = "operador"
ROLES_VALIDAS = (ROLE_ADMIN, ROLE_OPERADOR)
ROLE_ROTULOS = {ROLE_ADMIN: "Administrador", ROLE_OPERADOR: "Operador"}

# Credenciais iniciais
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

# Tipos de eventos para auditoria
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
# SEGURANÇA E AUDITORIA
# ---------------------------------------------------------------------------

def gerar_hash_senha(senha, salt=None):
    """Gera o hash PBKDF2-SHA256 com salt para armazenamento no banco."""
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
    """Valida a senha fornecida comparando com o hash salvo no banco."""
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
    """Remove caracteres especiais que possam alterar o formato do arquivo de log."""
    texto = "-" if valor is None else str(valor)
    texto = texto.replace("\r", " ").replace("\n", " ")
    texto = texto.replace("[", "(").replace("]", ")")
    return texto.strip() or "-"


def registrar_log(usuario, acao, detalhe=""):
    """Escreve um registro no arquivo security.log."""
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
    """Lê e retorna os últimos registros salvos em security.log."""
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
# PERSISTÊNCIA (SQLITE)
# ---------------------------------------------------------------------------

@contextmanager
def conexao_db():
    """Gerenciador de contexto da conexão SQLite com commit/rollback automático."""
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
    """Inicializa as tabelas no SQLite e insere o usuário admin inicial."""
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
    """Exceção para permissão de acesso negada."""


def exigir_admin(usuario_sessao, operacao):
    """Valida se o usuário autenticado possui perfil de Administrador."""
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
    """Valida se existe um usuário autenticado."""
    if not usuario_sessao:
        registrar_log("sem-sessao", ACAO_ACESSO_NEGADO,
                      "operação '{}' sem autenticação".format(operacao))
        raise AcessoNegado("Acesso Negado: é necessário estar autenticado.")


def validar_texto_obrigatorio(valor, nome_campo, tamanho_max=TAMANHO_MAX_TEXTO):
    """Valida se o texto preenchido é válido e não excede os limites."""
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
    """Valida o login e a senha do usuário."""
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
    """Cadastra um novo usuário no banco (apenas Admin)."""
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
    """Cadastra um visitante associado ao usuário logado."""
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
    """Retorna os visitantes ordenados do mais recente para o mais antigo."""
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
# INTERFACE GRÁFICA (TKINTER / TTK)
# ---------------------------------------------------------------------------

COR_FUNDO          = "#F1F5F9"
COR_CARTAO         = "#FFFFFF"
COR_BARRA          = "#0F172A"
COR_BARRA_ALT      = "#1E293B"
COR_BARRA_HOVER    = "#334155"
COR_PRIMARIA       = "#0369A1"
COR_PRIMARIA_HOVER = "#0284C7"
COR_SUCESSO        = "#047857"
COR_SUCESSO_HOVER  = "#059669"
COR_NEUTRA         = "#E2E8F0"
COR_NEUTRA_HOVER   = "#CBD5E1"
COR_TEXTO          = "#0F172A"
COR_TEXTO_SUAVE    = "#64748B"
COR_TEXTO_INVERSO  = "#FFFFFF"
COR_BORDA          = "#CBD5E1"
COR_ZEBRA          = "#F8FAFC"
COR_SELECAO        = "#DBEAFE"
COR_DESABILITADO   = "#94A3B8"
COR_ALERTA_FUNDO   = "#FEF3C7"
COR_ALERTA_TEXTO   = "#92400E"

FONTE = "Segoe UI"

_ESTILOS_BOTAO = (
    ("Primario.TButton", COR_PRIMARIA, COR_PRIMARIA_HOVER, COR_BARRA,
     (16, 10), (FONTE, 10, "bold")),
    ("PrimarioGrande.TButton", COR_PRIMARIA, COR_PRIMARIA_HOVER, COR_BARRA,
     (18, 16), (FONTE, 11, "bold")),
    ("Sucesso.TButton", COR_SUCESSO, COR_SUCESSO_HOVER, COR_BARRA,
     (16, 10), (FONTE, 10, "bold")),
    ("SucessoGrande.TButton", COR_SUCESSO, COR_SUCESSO_HOVER, COR_BARRA,
     (18, 16), (FONTE, 11, "bold")),
    ("Secundario.TButton", COR_NEUTRA, COR_NEUTRA_HOVER, COR_DESABILITADO,
     (16, 10), (FONTE, 10)),
    ("Barra.TButton", COR_BARRA_ALT, COR_BARRA_HOVER, COR_BARRA,
     (14, 8), (FONTE, 10, "bold")),
)


def configurar_tema(raiz):
    """Aplica o tema visual nos componentes do Tkinter."""
    estilo = ttk.Style(raiz)
    try:
        estilo.theme_use("clam")
    except tk.TclError:
        pass

    raiz.option_add("*TCombobox*Listbox.background", COR_CARTAO)
    raiz.option_add("*TCombobox*Listbox.foreground", COR_TEXTO)
    raiz.option_add("*TCombobox*Listbox.selectBackground", COR_SELECAO)
    raiz.option_add("*TCombobox*Listbox.selectForeground", COR_TEXTO)
    raiz.option_add("*TCombobox*Listbox.font", (FONTE, 10))

    estilo.configure(".", background=COR_FUNDO, foreground=COR_TEXTO,
                     font=(FONTE, 10))
    estilo.configure("TFrame", background=COR_FUNDO)
    estilo.configure("TLabel", background=COR_FUNDO, foreground=COR_TEXTO,
                     font=(FONTE, 10))

    estilo.configure("Cartao.TFrame", background=COR_CARTAO)
    estilo.configure("Cartao.TLabel", background=COR_CARTAO,
                     foreground=COR_TEXTO, font=(FONTE, 10))
    estilo.configure("CartaoSuave.TLabel", background=COR_CARTAO,
                     foreground=COR_TEXTO_SUAVE, font=(FONTE, 9))
    estilo.configure("RotuloCartao.TLabel", background=COR_CARTAO,
                     foreground=COR_TEXTO, font=(FONTE, 10, "bold"))
    estilo.configure("RodapeCartao.TLabel", background=COR_CARTAO,
                     foreground=COR_TEXTO_SUAVE, font=(FONTE, 8),
                     wraplength=320, justify="center")
    estilo.configure("Alerta.TLabel", background=COR_ALERTA_FUNDO,
                     foreground=COR_ALERTA_TEXTO, font=(FONTE, 9, "bold"),
                     padding=(12, 7))
    estilo.configure("Cartao.TLabelframe", background=COR_CARTAO,
                     bordercolor=COR_BORDA, relief="solid", borderwidth=1)
    estilo.configure("Cartao.TLabelframe.Label", background=COR_CARTAO,
                     foreground=COR_TEXTO, font=(FONTE, 11, "bold"))

    estilo.configure("BarraTitulo.TLabel", background=COR_BARRA,
                     foreground=COR_TEXTO_INVERSO, font=(FONTE, 13, "bold"))
    estilo.configure("BarraSub.TLabel", background=COR_BARRA,
                     foreground="#94A3B8", font=(FONTE, 9))
    estilo.configure("BadgeAdmin.TLabel", background=COR_PRIMARIA,
                     foreground=COR_TEXTO_INVERSO, font=(FONTE, 9, "bold"),
                     padding=(12, 5))
    estilo.configure("BadgeOperador.TLabel", background="#475569",
                     foreground="#F1F5F9", font=(FONTE, 9, "bold"),
                     padding=(12, 5))

    for nome, fundo, hover, pressionado, espacamento, fonte in _ESTILOS_BOTAO:
        estilo.configure(nome, background=fundo, foreground=COR_TEXTO_INVERSO,
                         font=fonte, borderwidth=0, relief="flat",
                         focusthickness=0, focuscolor=fundo,
                         padding=espacamento, anchor="center")
        estilo.map(
            nome,
            background=[("pressed", pressionado), ("active", hover),
                        ("disabled", "#94A3B8")],
            foreground=[("disabled", "#F8FAFC")],
        )

    estilo.configure("Secundario.TButton", foreground=COR_TEXTO)
    estilo.map("Secundario.TButton",
               background=[("pressed", COR_DESABILITADO),
                           ("active", COR_NEUTRA_HOVER),
                           ("disabled", "#F1F5F9")],
               foreground=[("disabled", COR_DESABILITADO)])
    estilo.configure("Barra.TButton", foreground=COR_TEXTO_INVERSO)

    estilo.configure("Campo.TEntry", fieldbackground=COR_CARTAO,
                     background=COR_CARTAO, foreground=COR_TEXTO,
                     bordercolor=COR_BORDA, lightcolor=COR_BORDA,
                     darkcolor=COR_BORDA, padding=(10, 8), font=(FONTE, 10))
    estilo.map("Campo.TEntry",
               bordercolor=[("focus", COR_PRIMARIA_HOVER)],
               lightcolor=[("focus", COR_PRIMARIA_HOVER)],
               darkcolor=[("focus", COR_PRIMARIA_HOVER)])

    estilo.configure("Campo.TCombobox", fieldbackground=COR_CARTAO,
                     background=COR_CARTAO, foreground=COR_TEXTO,
                     bordercolor=COR_BORDA, lightcolor=COR_BORDA,
                     darkcolor=COR_BORDA, arrowcolor=COR_TEXTO_SUAVE,
                     padding=(10, 6), font=(FONTE, 10))
    estilo.map("Campo.TCombobox",
               fieldbackground=[("readonly", COR_CARTAO)],
               selectbackground=[("readonly", COR_CARTAO)],
               selectforeground=[("readonly", COR_TEXTO)],
               bordercolor=[("focus", COR_PRIMARIA_HOVER)],
               lightcolor=[("focus", COR_PRIMARIA_HOVER)],
               darkcolor=[("focus", COR_PRIMARIA_HOVER)])

    estilo.configure("Treeview", background=COR_CARTAO,
                     fieldbackground=COR_CARTAO, foreground=COR_TEXTO,
                     bordercolor=COR_BORDA, lightcolor=COR_CARTAO,
                     darkcolor=COR_CARTAO, borderwidth=1, relief="solid",
                     font=(FONTE, 10), rowheight=30)
    estilo.map("Treeview",
               background=[("selected", COR_SELECAO)],
               foreground=[("selected", COR_TEXTO)])
    estilo.configure("Treeview.Heading", background=COR_BARRA_ALT,
                     foreground=COR_TEXTO_INVERSO, font=(FONTE, 10, "bold"),
                     relief="flat", borderwidth=0, padding=(10, 8))
    estilo.map("Treeview.Heading",
               background=[("active", COR_BARRA_HOVER)],
               foreground=[("active", COR_TEXTO_INVERSO)])

    estilo.configure("Vertical.TScrollbar", background=COR_NEUTRA,
                     troughcolor=COR_FUNDO, bordercolor=COR_FUNDO,
                     arrowcolor=COR_TEXTO_SUAVE, borderwidth=0, relief="flat")
    estilo.map("Vertical.TScrollbar",
               background=[("active", COR_NEUTRA_HOVER)])
    estilo.configure("TSeparator", background=COR_BORDA)


def criar_treeview(pai, colunas):
    """Cria um componente Treeview com barra de rolagem."""
    container = ttk.Frame(pai, style="Cartao.TFrame")
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
        tree.column(chave, width=largura, anchor=alinhamento,
                    stretch=(chave == colunas[-1][0]))

    tree.tag_configure("par", background=COR_ZEBRA)

    barra = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=barra.set)

    tree.grid(row=0, column=0, sticky="nsew")
    barra.grid(row=0, column=1, sticky="ns", padx=(6, 0))
    return container, tree


class DialogoBase(tk.Toplevel):
    """Classe base para janelas modais da aplicação."""

    def __init__(self, master, titulo, subtitulo=""):
        super().__init__(master)
        self.title(titulo)
        self.configure(bg=COR_FUNDO)
        self.transient(master.winfo_toplevel())
        self.protocol("WM_DELETE_WINDOW", self.fechar)
        self.bind("<Escape>", lambda evento: self.fechar())

        faixa = tk.Frame(self, bg=COR_BARRA)
        faixa.pack(fill="x")
        ttk.Label(faixa, text=titulo, style="BarraTitulo.TLabel").pack(
            anchor="w", padx=20, pady=(14, 0)
        )
        ttk.Label(faixa, text=subtitulo, style="BarraSub.TLabel").pack(
            anchor="w", padx=20, pady=(2, 14)
        )

        self.corpo = ttk.Frame(self, style="Cartao.TFrame", padding=20)
        self.corpo.pack(fill="both", expand=True, padx=16, pady=16)

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
    """Tela de login inicial da aplicação."""

    def __init__(self, master, app):
        super().__init__(master, padding=24)
        self.app = app
        self.var_usuario = tk.StringVar()
        self.var_senha = tk.StringVar()
        self._construir()

    def _construir(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        cartao = tk.Frame(self, bg=COR_CARTAO, highlightthickness=1,
                          highlightbackground=COR_BORDA,
                          highlightcolor=COR_BORDA)
        cartao.grid(row=0, column=0)

        faixa = tk.Frame(cartao, bg=COR_BARRA)
        faixa.pack(fill="x")
        ttk.Label(
            faixa,
            text="SISTEMA DE CONTROLE DE ACESSO",
            style="BarraTitulo.TLabel",
        ).pack(padx=30, pady=(22, 2))
        ttk.Label(
            faixa,
            text="PORTARIA — acesso restrito a usuários autorizados",
            style="BarraSub.TLabel",
        ).pack(padx=30, pady=(0, 20))

        corpo = ttk.Frame(cartao, style="Cartao.TFrame", padding=(30, 26))
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(0, weight=1)

        ttk.Label(corpo, text="Usuário", style="RotuloCartao.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self.entry_usuario = ttk.Entry(
            corpo, textvariable=self.var_usuario, width=34, style="Campo.TEntry"
        )
        self.entry_usuario.grid(row=1, column=0, sticky="we", pady=(5, 16))

        ttk.Label(corpo, text="Senha", style="RotuloCartao.TLabel").grid(
            row=2, column=0, sticky="w"
        )
        self.entry_senha = ttk.Entry(
            corpo, textvariable=self.var_senha, width=34, show="*",
            style="Campo.TEntry",
        )
        self.entry_senha.grid(row=3, column=0, sticky="we", pady=(5, 22))

        ttk.Button(
            corpo, text="Entrar", style="Sucesso.TButton", command=self._entrar
        ).grid(row=4, column=0, sticky="we")
        ttk.Button(
            corpo, text="Sair", style="Secundario.TButton", command=self._cancelar
        ).grid(row=5, column=0, sticky="we", pady=(10, 0))

        ttk.Label(
            corpo,
            text="As tentativas de acesso são registradas em security.log.",
            style="RodapeCartao.TLabel",
        ).grid(row=6, column=0, pady=(20, 0))

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
    """Painel principal de controle da portaria."""

    def __init__(self, master, app):
        super().__init__(master, padding=0)
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

        self._construir_barra_superior()

        conteudo = ttk.Frame(self, padding=(20, 18))
        conteudo.grid(row=1, column=0, sticky="nsew")
        conteudo.columnconfigure(0, weight=1)
        conteudo.rowconfigure(0, weight=1)
        conteudo.rowconfigure(1, weight=1)

        self._card_acoes_rapidas(conteudo)
        if self._eh_admin():
            self._card_administracao(conteudo)
        else:
            self._card_operador(conteudo)

    def _construir_barra_superior(self):
        barra = tk.Frame(self, bg=COR_BARRA)
        barra.grid(row=0, column=0, sticky="we")
        barra.columnconfigure(0, weight=1)

        textos = tk.Frame(barra, bg=COR_BARRA)
        textos.grid(row=0, column=0, sticky="w", padx=20, pady=14)
        ttk.Label(
            textos,
            text="SISTEMA DE CONTROLE DE ACESSO | PORTARIA",
            style="BarraTitulo.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            textos,
            text="Painel de Portaria — registros de entrada e auditoria",
            style="BarraSub.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        direita = tk.Frame(barra, bg=COR_BARRA)
        direita.grid(row=0, column=1, sticky="e", padx=20)

        admin = self._eh_admin()
        estilo_badge = "BadgeAdmin.TLabel" if admin else "BadgeOperador.TLabel"
        rotulo = ROLE_ROTULOS.get(self.usuario["role"], self.usuario["role"]).upper()
        ttk.Label(
            direita,
            text="•  {}   [ {} ]".format(self.usuario["username"], rotulo),
            style=estilo_badge,
        ).pack(side="left", padx=(0, 16))

        ttk.Button(
            direita, text="Sair (Logout)", style="Barra.TButton",
            command=self._logout,
        ).pack(side="left")

    def _card_acoes_rapidas(self, pai):
        card = ttk.LabelFrame(
            pai, text="Ações Rápidas de Portaria", style="Cartao.TLabelframe",
            padding=(18, 14),
        )
        card.grid(row=0, column=0, sticky="nsew", pady=(0, 16))
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)

        ttk.Label(
            card,
            text="Registre a entrada de um visitante ou consulte o histórico de acessos.",
            style="CartaoSuave.TLabel",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Button(
            card, text="Cadastrar Visitante", style="SucessoGrande.TButton",
            command=self._abrir_cadastro_visitante,
        ).grid(row=1, column=0, sticky="we", padx=(0, 8))

        ttk.Button(
            card, text="Ver Visitantes", style="PrimarioGrande.TButton",
            command=self._abrir_lista_visitantes,
        ).grid(row=1, column=1, sticky="we", padx=(8, 0))

    def _card_administracao(self, pai):
        card = ttk.LabelFrame(
            pai, text="Painel de Administração", style="Cartao.TLabelframe",
            padding=(18, 14),
        )
        card.grid(row=1, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)

        ttk.Label(
            card,
            text="ÁREA RESTRITA — disponível somente para o perfil Administrador",
            style="Alerta.TLabel",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Label(
            card,
            text="Cadastro de credenciais de acesso e leitura da trilha de auditoria.",
            style="CartaoSuave.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 12))

        ttk.Button(
            card, text="Cadastrar Novo Usuário (Admin/Operador)",
            style="Primario.TButton", command=self._abrir_cadastro_usuario,
        ).grid(row=2, column=0, sticky="we", padx=(0, 8))

        ttk.Button(
            card, text="Ver Logs", style="Secundario.TButton",
            command=self._abrir_logs,
        ).grid(row=2, column=1, sticky="we", padx=(8, 0))

    def _card_operador(self, pai):
        card = ttk.LabelFrame(
            pai, text="Permissões do seu perfil", style="Cartao.TLabelframe",
            padding=(18, 14),
        )
        card.grid(row=1, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)

        ttk.Label(
            card, text="PERFIL OPERADOR", style="Alerta.TLabel"
        ).grid(row=0, column=0, sticky="w", pady=(0, 14))

        ttk.Label(
            card,
            text="Seu perfil permite cadastrar visitantes e consultar a lista de "
                 "acessos. O cadastro de usuários e a leitura dos logs de "
                 "segurança são exclusivos do perfil Administrador.",
            style="Cartao.TLabel", justify="left", wraplength=620,
        ).grid(row=1, column=0, sticky="w")

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
        super().__init__(master, "Cadastrar Visitante",
                         "Registro de entrada no painel de portaria")
        self.app = app
        self.usuario = usuario
        self.var_nome = tk.StringVar()
        self.var_documento = tk.StringVar()
        self._construir()

    def _construir(self):
        corpo = self.corpo
        corpo.columnconfigure(0, weight=1)

        ttk.Label(corpo, text="Nome completo", style="RotuloCartao.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        entrada_nome = ttk.Entry(
            corpo, textvariable=self.var_nome, width=38, style="Campo.TEntry"
        )
        entrada_nome.grid(row=1, column=0, sticky="we", pady=(5, 16))

        ttk.Label(corpo, text="Documento (RG/CPF)", style="RotuloCartao.TLabel").grid(
            row=2, column=0, sticky="w"
        )
        entrada_documento = ttk.Entry(
            corpo, textvariable=self.var_documento, width=38, style="Campo.TEntry"
        )
        entrada_documento.grid(row=3, column=0, sticky="we", pady=(5, 22))

        botoes = ttk.Frame(corpo, style="Cartao.TFrame")
        botoes.grid(row=4, column=0, sticky="we")
        botoes.columnconfigure(0, weight=1)
        botoes.columnconfigure(1, weight=1)

        ttk.Button(
            botoes, text="Salvar", style="Sucesso.TButton", command=self._salvar
        ).grid(row=0, column=0, sticky="we", padx=(0, 6))
        ttk.Button(
            botoes, text="Cancelar", style="Secundario.TButton",
            command=self.fechar,
        ).grid(row=0, column=1, sticky="we", padx=(6, 0))

        entrada_nome.bind("<Return>", lambda evento: entrada_documento.focus_set())
        entrada_documento.bind("<Return>", self._salvar)
        self.after(50, entrada_nome.focus_set)

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
    """Janela modal para cadastro de usuários (Admin)."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Cadastrar Novo Usuário",
                         "Criação de credenciais de acesso — área restrita")
        self.app = app
        self.usuario = usuario
        self.var_username = tk.StringVar()
        self.var_senha = tk.StringVar()
        self.var_confirmacao = tk.StringVar()
        self.var_perfil = tk.StringVar(value=ROLE_ROTULOS[ROLE_OPERADOR])
        self._construir()

    def _construir(self):
        corpo = self.corpo
        corpo.columnconfigure(0, weight=1)

        linha = 0
        entradas = []
        for rotulo, variavel, oculto in (
            ("Usuário (login)", self.var_username, False),
            ("Senha", self.var_senha, True),
            ("Confirmar senha", self.var_confirmacao, True),
        ):
            ttk.Label(corpo, text=rotulo, style="RotuloCartao.TLabel").grid(
                row=linha, column=0, sticky="w"
            )
            entrada = ttk.Entry(
                corpo, textvariable=variavel, width=36,
                show="*" if oculto else "", style="Campo.TEntry",
            )
            entrada.grid(row=linha + 1, column=0, sticky="we", pady=(5, 14))
            entradas.append(entrada)
            linha += 2

        ttk.Label(corpo, text="Perfil de acesso", style="RotuloCartao.TLabel").grid(
            row=linha, column=0, sticky="w"
        )
        ttk.Combobox(
            corpo, textvariable=self.var_perfil, state="readonly",
            values=(ROLE_ROTULOS[ROLE_ADMIN], ROLE_ROTULOS[ROLE_OPERADOR]),
            style="Campo.TCombobox",
        ).grid(row=linha + 1, column=0, sticky="we", pady=(5, 16))
        linha += 2

        ttk.Label(
            corpo,
            text="A senha é gravada apenas em formato hash (PBKDF2-SHA256).",
            style="CartaoSuave.TLabel",
        ).grid(row=linha, column=0, sticky="w", pady=(0, 18))
        linha += 1

        botoes = ttk.Frame(corpo, style="Cartao.TFrame")
        botoes.grid(row=linha, column=0, sticky="we")
        botoes.columnconfigure(0, weight=1)
        botoes.columnconfigure(1, weight=1)

        ttk.Button(
            botoes, text="Salvar", style="Sucesso.TButton", command=self._salvar
        ).grid(row=0, column=0, sticky="we", padx=(0, 6))
        ttk.Button(
            botoes, text="Cancelar", style="Secundario.TButton",
            command=self.fechar,
        ).grid(row=0, column=1, sticky="we", padx=(6, 0))

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
    """Janela modal para exibição dos visitantes cadastrados."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Visitantes Cadastrados",
                         "Histórico de entradas registradas na portaria")
        self.app = app
        self.usuario = usuario
        self._construir()
        self._carregar()

    def _construir(self):
        self.geometry("960x470")
        corpo = self.corpo
        corpo.rowconfigure(0, weight=1)
        corpo.columnconfigure(0, weight=1)

        colunas = [
            ("id", "ID", 60, "center"),
            ("nome", "Nome", 250, "w"),
            ("documento", "Documento", 150, "w"),
            ("data_registro", "Data do Registro", 150, "w"),
            ("registrado_por", "Registrado por", 150, "w"),
        ]
        container, self.tree = criar_treeview(corpo, colunas)
        container.grid(row=0, column=0, sticky="nsew")

        rodape = ttk.Frame(corpo, style="Cartao.TFrame")
        rodape.grid(row=1, column=0, sticky="we", pady=(14, 0))
        rodape.columnconfigure(0, weight=1)

        self.var_total = tk.StringVar(value="Total de visitantes: 0")
        ttk.Label(rodape, textvariable=self.var_total,
                  style="CartaoSuave.TLabel").grid(row=0, column=0, sticky="w")

        ttk.Button(rodape, text="Atualizar", style="Primario.TButton",
                   command=self._carregar).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(rodape, text="Fechar", style="Secundario.TButton",
                   command=self.fechar).grid(row=0, column=2)

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

        if visitantes:
            self.var_total.set("Total de visitantes: {}".format(len(visitantes)))
        else:
            self.var_total.set("Nenhum visitante registrado até o momento.")


class DialogoLogs(DialogoBase):
    """Janela modal para exibição da trilha de auditoria (Admin)."""

    def __init__(self, master, app, usuario):
        super().__init__(master, "Logs de Segurança",
                         "Trilha de auditoria registrada em security.log")
        self.app = app
        self.usuario = usuario
        self._construir()
        self._carregar()

    def _construir(self):
        self.geometry("1000x520")
        corpo = self.corpo
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

        rodape = ttk.Frame(corpo, style="Cartao.TFrame")
        rodape.grid(row=1, column=0, sticky="we", pady=(14, 0))
        rodape.columnconfigure(0, weight=1)

        self.var_total = tk.StringVar(value="Registros exibidos: 0")
        ttk.Label(rodape, textvariable=self.var_total,
                  style="CartaoSuave.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(rodape, text="Arquivo: {}".format(LOG_PATH),
                  style="CartaoSuave.TLabel").grid(row=1, column=0, sticky="w")

        ttk.Button(rodape, text="Atualizar", style="Primario.TButton",
                   command=self._carregar).grid(row=0, column=1, rowspan=2,
                                                padx=(0, 6))
        ttk.Button(rodape, text="Fechar", style="Secundario.TButton",
                   command=self.fechar).grid(row=0, column=2, rowspan=2)

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

        if registros:
            self.var_total.set("Registros exibidos: {}".format(len(registros)))
        else:
            self.var_total.set("Nenhum registro de auditoria encontrado.")


class AplicacaoVisitantes(tk.Tk):
    """Classe principal da aplicação."""

    def __init__(self):
        super().__init__()
        self.title("Sistema de Controle de Visitantes")
        self.geometry("1000x660")
        self.minsize(900, 580)
        self.configure(bg=COR_FUNDO)

        self.usuario_logado = None
        self.tela_atual = None

        configurar_tema(self)

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.report_callback_exception = self._tratar_excecao_tk

        self.mostrar_login()

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
