#!/bin/bash

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Função para executar comandos MySQL
execute_mysql_command() {
    if mysql "$@"; then
        return 0
    else
        return 1
    fi
}

echo -e "${GREEN}Iniciando configuração do banco de dados...${NC}"

# Solicitar credenciais do MySQL
read -p "Digite o usuário root do MySQL: " MYSQL_ROOT
read -s -p "Digite a senha do root do MySQL: " MYSQL_ROOT_PASSWORD
echo

# Criar banco de dados
echo -e "\n${GREEN}Criando banco de dados password_vault...${NC}"
if execute_mysql_command -u "$MYSQL_ROOT" -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS password_vault;"; then
    echo -e "${GREEN}✓ Banco de dados criado com sucesso${NC}"
else
    echo -e "${RED}✗ Erro ao criar banco de dados${NC}"
    exit 1
fi

# Criar usuário do banco
echo -e "\n${GREEN}Criando usuário vault_user...${NC}"
if execute_mysql_command -u "$MYSQL_ROOT" -p"$MYSQL_ROOT_PASSWORD" -e "CREATE USER IF NOT EXISTS 'vault_user'@'localhost' IDENTIFIED BY 'sua_senha_segura';"; then
    echo -e "${GREEN}✓ Usuário criado com sucesso${NC}"
else
    echo -e "${RED}✗ Erro ao criar usuário${NC}"
    exit 1
fi

# Conceder privilégios
echo -e "\n${GREEN}Concedendo privilégios ao usuário...${NC}"
if execute_mysql_command -u "$MYSQL_ROOT" -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON password_vault.* TO 'vault_user'@'localhost'; FLUSH PRIVILEGES;"; then
    echo -e "${GREEN}✓ Privilégios concedidos com sucesso${NC}"
else
    echo -e "${RED}✗ Erro ao conceder privilégios${NC}"
    exit 1
fi

# Criar tabelas
echo -e "\n${GREEN}Criando tabelas...${NC}"
if execute_mysql_command -u "$MYSQL_ROOT" -p"$MYSQL_ROOT_PASSWORD" password_vault < ../src/main/resources/schema.sql; then
    echo -e "${GREEN}✓ Tabelas criadas com sucesso${NC}"
else
    echo -e "${RED}✗ Erro ao criar tabelas${NC}"
    exit 1
fi

echo -e "\n${GREEN}Configuração do banco de dados concluída com sucesso!${NC}" 