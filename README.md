# Sistema de Controlo de Visitantes (Portaria)

Aplicação desktop desenvolvida em **Python (Tkinter)** com base de dados relacional **SQLite**, focada em Segurança da Informação e Controlo de Acessos.

## 🔒 Funcionalidades e Mecanismos de Segurança
* **Autenticação Obrigatória:** Acesso restrito através de utilizador e palavra-passe.
* **Proteção de Credenciais:** As palavras-passe são protegidas com **PBKDF2** + **SHA-256** e *salt* aleatório de 16 bytes por utilizador.
* **Controlo de Acesso por Perfis (RBAC):**
  * **Administrador:** Acesso total (gestão de utilizadores, registo de visitantes e visualização de logs).
  * **Operador:** Acesso restrito (apenas registo e consulta de visitantes).
* **Rastreabilidade e Auditoria:** Registo automático de eventos em `security.log` (logins, tentativas inválidas e utilizador responsável por cada visitante).
* **Migração Automática:** Suporte a migração de esquema de base de dados (`ALTER TABLE`) para campos legados.

## 🚀 Como Executar
1. Certifique-se de ter o **Python 3** instalado.
2. Execute o ficheiro principal através do terminal ou linha de comandos:
   ```bash
   python sistema_visitantes.py
