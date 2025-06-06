# Gerenciador de Senhas Seguro

Um gerenciador de senhas seguro desenvolvido em Java, com foco em segurança da informação e boas práticas de desenvolvimento.

## 🚀 Funcionalidades

- Cadastro seguro de credenciais (serviço, e-mail, senha)
- Criptografia AES para armazenamento seguro
- Autenticação de dois fatores (2FA) via Google Authenticator
- Geração de senhas fortes e aleatórias
- Verificação de vazamento de senhas via API haveibeenpwned.com
- Interface de linha de comando (CLI) amigável
- Armazenamento local seguro em arquivo JSON criptografado

## 🛡️ Medidas de Segurança Implementadas

- Criptografia AES para dados sensíveis
- Proteção contra SQL Injection (não utiliza banco de dados)
- Validação e sanitização de inputs
- Autenticação de dois fatores
- Senhas armazenadas com hash bcrypt
- Verificação de força de senhas
- Proteção contra vazamentos conhecidos

## 📋 Pré-requisitos

- Java 17 ou superior
- Maven 3.6 ou superior
- Conexão com internet (para verificação de vazamentos)

## 🚀 Como executar

1. Clone o repositório
2. Execute `mvn clean install`
3. Execute `java -jar target/password-vault-1.0-SNAPSHOT.jar`

## 🧪 Testes

Execute os testes unitários com:
```bash
mvn test
```

## 📁 Estrutura do Projeto

```
src/
├── main/
│   └── java/
│       └── com/
│           └── passwordvault/
│               ├── model/        # Classes de modelo
│               ├── controller/   # Controladores
│               ├── security/     # Classes de segurança
│               ├── repository/   # Persistência
│               └── utils/        # Utilitários
└── test/
    └── java/
        └── com/
            └── passwordvault/    # Testes unitários
```

## 🔒 Vulnerabilidades Corrigidas

- Implementação de salt único para cada senha
- Proteção contra timing attacks
- Sanitização de inputs
- Validação de força de senhas
- Proteção contra vazamentos conhecidos

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes. 