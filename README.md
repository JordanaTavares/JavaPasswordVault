# Java Password Vault 🔐

[![Java Version](https://img.shields.io/badge/Java-17%2B-orange)](https://www.oracle.com/java/technologies/downloads/#java17)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--GCM-green)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![2FA](https://img.shields.io/badge/2FA-Google%20Authenticator-yellow)](https://github.com/google/google-authenticator)

Um gerenciador de senhas seguro e fácil de usar, desenvolvido em Java. Proteja suas senhas com criptografia de nível militar e autenticação de dois fatores.

## 📋 Índice
- [Recursos](#recursos)
- [Requisitos do Sistema](#requisitos-do-sistema)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Segurança](#segurança)

## ✨ Recursos

- 🔒 Criptografia AES-GCM de última geração
- 👤 Sistema de usuário mestre com senha única
- 📱 Autenticação de dois fatores (2FA) com Google Authenticator
- 🔍 Verificação de senhas vazadas
- 🎨 Interface colorida e amigável
- 💾 Armazenamento seguro de credenciais
- ⚡ Desempenho rápido e eficiente
- 🔄 Sincronização automática entre banco local e remoto
- 📊 Gerenciamento inteligente de conexões com banco de dados
- 🛡️ Proteção contra vazamento de recursos

## 💻 Requisitos do Sistema

- Java 17 ou superior
- Sistema operacional: Windows, macOS ou Linux
- Espaço em disco: 100MB mínimo
- Memória RAM: 256MB mínimo

## 🚀 Instalação

### Pré-requisitos

1. Instale o Git:
   ```bash
   # No Ubuntu/Debian
   sudo apt update
   sudo apt install git

   # No Windows
   # Baixe e instale do site oficial: https://git-scm.com/download/win
   ```

2. Instale o Java 17:
   ```bash
   # No Ubuntu/Debian
   sudo apt install openjdk-17-jdk

   # No Windows
   # Baixe e instale do site oficial: https://www.oracle.com/java/technologies/downloads/#java17
   ```

3. Instale o Maven:
   ```bash
   # No Ubuntu/Debian
   sudo apt install maven

   # No Windows
   # Baixe de: https://maven.apache.org/download.cgi
   # Extraia e adicione ao PATH do sistema
   ```

### Clonando e Configurando o Projeto

1. Clone o repositório:
   ```bash
   git clone https://github.com/JordanaTavares/JavaPasswordVault.git
   cd JavaPasswordVault
   ```

2. Compile o projeto:
   ```bash
   mvn clean install
   ```

3. Verifique a instalação do Java:
   ```bash
   java -version   # Deve mostrar versão 17 ou superior
   mvn -version    # Deve mostrar que está usando Java 17
   ```

### Executando o Projeto

O comando comprovado para executar o projeto é:

```bash
# Compilar e executar o projeto
mvn compile exec:java -Dexec.mainClass="com.passwordvault.Main"
```

Este comando:
- Compila o código fonte
- Executa a classe principal diretamente
- Gerencia automaticamente as dependências
- Mantém o classpath correto

> 💡 **Dica**: Este é o método mais confiável para executar o projeto, pois garante que todas as dependências estejam disponíveis e que o classpath esteja configurado corretamente.

Alternativamente, você também pode usar:

```bash
# Opção 1: Gerar o JAR e executar
mvn clean install
java -jar target/password-vault-1.0-SNAPSHOT.jar

# Opção 2: Executar diretamente com Maven
mvn spring-boot:run
```

Mas o primeiro método (`mvn compile exec:java`) é o mais recomendado e testado.

### Verificando a Execução

Após executar o comando, você deve ver:
1. O logo do Password Vault
2. Menu de login/registro
3. Prompt para criar usuário mestre (primeira execução)

Se encontrar algum erro, verifique:
- Se o Maven está instalado (`mvn -version`)
- Se o Java 17 está configurado (`java -version`)
- Se o MySQL está rodando (`systemctl status mysql`)

### Atualizando o Projeto

Para atualizar o projeto com as últimas alterações:

```bash
git pull origin master
mvn clean install
```

### Solução de Problemas Comuns

1. Erro de versão do Java:
   ```bash
   # Verifique a versão do Java
   java -version
   
   # Configure o JAVA_HOME se necessário
   export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
   ```

2. Erro de permissão no Linux:
   ```bash
   # Dê permissão de execução ao JAR
   chmod +x target/password-vault-1.0.jar
   ```

3. Erro de porta em uso:
   ```bash
   # Verifique se a porta está em uso
   netstat -tulpn | grep 8080
   
   # Mate o processo se necessário
   kill -9 $(lsof -t -i:8080)
   ```

### 🎯 Iniciando o Projeto pela Primeira Vez

Siga estes passos na ordem exata para iniciar o projeto:

1. Prepare o ambiente:
   ```bash
   # Entre na pasta do projeto
   cd JavaPasswordVault

   # Limpe qualquer build anterior
   mvn clean

   # Instale as dependências e compile
   mvn install
   ```

2. Configure o banco de dados:
   ```bash
   # Entre no MySQL
   mysql -u root -p
   
   # Digite sua senha do MySQL quando solicitado
   
   # No prompt do MySQL, execute:
   CREATE DATABASE password_vault;
   CREATE USER 'vault_user'@'localhost' IDENTIFIED BY 'sua_senha_segura';
   GRANT ALL PRIVILEGES ON password_vault.* TO 'vault_user'@'localhost';
   FLUSH PRIVILEGES;
   exit;
   ```

3. Configure o arquivo de propriedades:
   ```bash
   # Crie o arquivo application.properties
   mkdir -p src/main/resources
   nano src/main/resources/application.properties
   ```
   
   Cole o seguinte conteúdo (substitua os valores conforme necessário):
   ```properties
   # Banco de Dados Local
   db.local.url=jdbc:mysql://localhost:3306/password_vault
   db.local.user=vault_user
   db.local.password=sua_senha_segura

   # Configurações de Segurança
   security.encryption.iterations=310000
   security.token.expiration=3600
   security.session.timeout=15

   # Configurações do Sistema
   app.name=Password Vault
   app.version=1.0
   app.locale=pt_BR
   ```

4. Inicie o projeto:
   ```bash
   # Opção 1: Usando Maven
   mvn spring-boot:run

   # OU Opção 2: Usando o JAR
   java -jar target/password-vault-1.0.jar
   ```

5. Primeiro acesso:
   - O sistema solicitará a criação de uma conta de usuário mestre
   - Digite um nome de usuário
   - Crie uma senha mestra forte (mínimo 12 caracteres)
   - Siga as instruções para configurar o Google Authenticator
   - IMPORTANTE: Guarde o código de backup do 2FA em local seguro!

6. Verificando se tudo está funcionando:
   - Tente fazer login com suas credenciais
   - Confirme que o 2FA está funcionando
   - Adicione uma senha de teste
   - Verifique se consegue recuperar a senha adicionada

### Checklist de Verificação ✅

Confirme que:
- [ ] MySQL está rodando (`systemctl status mysql`)
- [ ] Banco de dados foi criado (`mysql -u vault_user -p password_vault`)
- [ ] application.properties está configurado corretamente
- [ ] Todas as dependências foram instaladas (`mvn dependency:tree`)
- [ ] Porta 8080 está livre (`netstat -tulpn | grep 8080`)
- [ ] Java 17 está instalado (`java -version`)

### Comandos Úteis para Inicialização

```bash
# Verificar status do MySQL
sudo systemctl status mysql

# Reiniciar MySQL se necessário
sudo systemctl restart mysql

# Verificar logs em tempo real
tail -f logs/password-vault.log

# Verificar portas em uso
netstat -tulpn | grep 8080

# Verificar versão do Java
java -version

# Verificar versão do Maven
mvn -version
```

### Problemas Comuns na Primeira Execução

1. Erro de conexão com banco:
   ```bash
   # Verifique se o MySQL está rodando
   sudo systemctl status mysql
   
   # Teste a conexão
   mysql -u vault_user -p password_vault
   ```

2. Erro de permissão:
   ```bash
   # Ajuste as permissões do diretório
   chmod -R 755 .
   chmod 600 src/main/resources/application.properties
   ```

3. Erro de porta em uso:
   ```bash
   # Libere a porta 8080
   sudo kill -9 $(lsof -t -i:8080)
   ```

## 🏗️ Arquitetura do Sistema

### Gerenciamento de Conexões

O sistema utiliza um gerenciador de conexões inteligente que:
- Mantém registro de todas as conexões ativas
- Fecha automaticamente conexões não utilizadas
- Garante limpeza de recursos ao encerrar o programa
- Previne vazamentos de memória e conexões
- Utiliza pool de conexões para melhor performance

### Segurança de Dados

- Criptografia AES-GCM 256 bits para senhas
- Salt único por usuário
- Chaves de criptografia nunca são armazenadas em disco
- Timeout automático de sessão
- Proteção contra SQL Injection
- Validação de entrada em todas as operações

### Sincronização

- Sincronização bidirecional entre banco local e remoto
- Resolução automática de conflitos baseada em timestamp
- Suporte a modo offline com persistência local
- Merge inteligente de dados na sincronização
- Backup automático antes de sincronizar

## ⚙️ Configuração do Ambiente

### Configuração do Banco de Dados Local

1. Instale o MySQL:
   ```bash
   # No Ubuntu/Debian
   sudo apt update
   sudo apt install mysql-server

   # No Windows
   # Baixe e instale do site oficial: https://dev.mysql.com/downloads/installer/
   ```

2. Acesse o MySQL:
   ```bash
   # No Linux
   sudo mysql

   # No Windows
   mysql -u root -p
   ```

3. Crie o banco de dados e usuário:
   ```sql
   CREATE DATABASE password_vault;
   CREATE USER 'vault_user'@'localhost' IDENTIFIED BY 'sua_senha_segura';
   GRANT ALL PRIVILEGES ON password_vault.* TO 'vault_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

### Configuração do Railway

1. Crie uma conta no Railway (https://railway.app)

2. Crie um novo projeto:
   - Clique em "New Project"
   - Selecione "Provision MySQL"
   - Aguarde a criação do banco

3. Obtenha as credenciais:
   - Vá para a aba "Connect"
   - Copie as informações de conexão:
     - Host
     - Port
     - Database
     - Username
     - Password

### Configuração do application.properties

1. Crie o arquivo `application.properties` na pasta `src/main/resources`:
   ```properties
   # Configurações do Banco Local
   db.local.url=jdbc:mysql://localhost:3306/password_vault
   db.local.user=vault_user
   db.local.password=sua_senha_segura

   # Configurações do Railway (substitua com suas credenciais)
   db.remote.url=jdbc:mysql://seu_host_railway:porta/seu_banco
   db.remote.user=seu_usuario_railway
   db.remote.password=sua_senha_railway

   # Configurações de Segurança
   security.encryption.iterations=310000
   security.token.expiration=3600
   security.session.timeout=15

   # Configurações do Sistema
   app.name=Password Vault
   app.version=1.0
   app.locale=pt_BR

   # Configurações de Conexão
   db.connection.timeout=30
   db.connection.pool.size=10
   db.connection.idle.timeout=300
   ```

2. Ajuste as permissões do arquivo (Linux/Mac):
   ```bash
   chmod 600 src/main/resources/application.properties
   ```

### Estrutura do Banco de Dados

O sistema criará automaticamente as seguintes tabelas:

1. Tabela de Usuários:
   ```sql
   CREATE TABLE users (
       id VARCHAR(36) PRIMARY KEY,
       username VARCHAR(50) UNIQUE NOT NULL,
       password_hash VARCHAR(255) NOT NULL,
       two_factor_secret VARCHAR(32) NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       last_login TIMESTAMP
   );
   ```

2. Tabela de Credenciais:
   ```sql
   CREATE TABLE credentials (
       id VARCHAR(36) PRIMARY KEY,
       user_id VARCHAR(36) NOT NULL,
       service VARCHAR(100) NOT NULL,
       username VARCHAR(100) NOT NULL,
       encrypted_password TEXT NOT NULL,
       notes TEXT,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
       FOREIGN KEY (user_id) REFERENCES users(id)
   );
   ```

### Verificação da Instalação

Para verificar se tudo está configurado corretamente:

1. Teste a conexão local:
   ```bash
   mysql -u vault_user -p password_vault
   ```

2. Verifique as tabelas:
   ```sql
   SHOW TABLES;
   ```

3. Teste a conexão com Railway:
   ```bash
   mysql -h seu_host_railway -P porta -u usuario -p nome_banco
   ```

### Monitoramento do Sistema

Para monitorar o estado das conexões e recursos:

```bash
# Verificar conexões ativas do MySQL
mysql -u root -p -e "SHOW PROCESSLIST;"

# Monitorar uso de memória da JVM
jstat -gc $(pgrep -f password-vault) 1000

# Verificar threads ativas
jstack $(pgrep -f password-vault)
```

### Solução de Problemas

1. Problemas de Conexão:
   ```bash
   # Reiniciar serviço MySQL
   sudo systemctl restart mysql

   # Limpar cache do MySQL
   sudo /etc/init.d/mysql flush-hosts
   ```

2. Problemas de Performance:
   ```bash
   # Otimizar tabelas
   mysqlcheck -o password_vault -u root -p

   # Verificar índices
   mysql -u root -p password_vault -e "SHOW INDEX FROM credentials;"
   ```

3. Problemas de Memória:
   ```bash
   # Aumentar heap da JVM
   java -Xmx512m -jar password-vault.jar
   ```

## 📖 Como Usar

### Primeiro Acesso

1. Ao iniciar o programa pela primeira vez, você será solicitado a criar uma conta de usuário mestre
2. Digite uma senha mestra forte (mínimo 12 caracteres, incluindo letras, números e símbolos)
3. Configure a autenticação de dois fatores usando o Google Authenticator
4. Guarde o código de backup em um local seguro

### Uso Diário

1. Inicie o programa
2. Digite sua senha mestra
3. Insira o código 2FA do Google Authenticator
4. Use o menu principal para:
   - Adicionar novas senhas
   - Visualizar senhas existentes
   - Editar credenciais
   - Excluir senhas antigas

### Comandos do Menu

- `1` - Adicionar nova senha
- `2` - Listar todas as senhas
- `3` - Buscar senha específica
- `4` - Editar senha existente
- `5` - Excluir senha
- `0` - Sair do programa

## 🔐 Segurança

### Recursos de Segurança

- Criptografia AES-GCM 256 bits
- Derivação de chave PBKDF2 com 310000 iterações
- Hash de senha com BCrypt
- Verificação de senhas comprometidas
- Autenticação de dois fatores
- Timeout automático por inatividade

### Boas Práticas

- Nunca compartilhe sua senha mestra
- Use o 2FA sempre
- Faça backup regular dos seus dados
- Mantenha o sistema operacional atualizado
- Use senhas únicas para cada serviço

## 🤝 Suporte

Para suporte ou dúvidas, abra uma issue no GitHub ou contate o administrador do sistema.

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

Desenvolvido com ❤️ para sua segurança digital. 