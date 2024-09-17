gostei do projeto e vi que ja tem 10 anos resolvi atualisar com as novas tecnologias
Para criar um sistema simples em PHP para locação automática de paletes em um sistema de endereços dividido em ruas e apartamentos, você pode seguir as etapas abaixo. Este exemplo irá criar um sistema básico que distribui paletes entre endereços de maneira automatizada.

### Estrutura do Sistema

1. **Banco de Dados**: Crie um banco de dados com tabelas para endereços e paletes.
2. **Script PHP**: Escreva um script PHP que distribua paletes automaticamente entre os endereços disponíveis.

### Passo 1: Estrutura do Banco de Dados

Vamos supor que você tenha duas tabelas: `enderecos` e `paletes`.

**Tabela `enderecos`**:
```sql
CREATE TABLE enderecos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rua VARCHAR(255) NOT NULL,
    apartamento INT NOT NULL
);
```

**Tabela `paletes`**:
```sql
CREATE TABLE paletes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    endereco_id INT,
    FOREIGN KEY (endereco_id) REFERENCES enderecos(id)
);
```

### Passo 2: Script PHP para Locação Automática de Paletes

Este script distribui 100 paletes entre os endereços disponíveis.

**1. Conecte-se ao Banco de Dados**

```php
<?php
$host = 'localhost'; // ou o seu host
$db = 'nome_do_banco'; // substitua pelo nome do seu banco de dados
$user = 'usuario'; // substitua pelo nome de usuário
$pass = 'senha'; // substitua pela senha

$pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
?>
```

**2. Função para Distribuir Paletes**

```php
<?php
// Função para distribuir paletes
function distribuirPaletes($pdo, $numPaletes) {
    // Obtém todos os endereços
    $stmt = $pdo->query('SELECT id FROM enderecos');
    $enderecos = $stmt->fetchAll(PDO::FETCH_COLUMN);

    if (empty($enderecos)) {
        echo "Nenhum endereço disponível.";
        return;
    }

    // Distribui os paletes
    $numEnderecos = count($enderecos);
    for ($i = 0; $i < $numPaletes; $i++) {
        $enderecoId = $enderecos[$i % $numEnderecos];
        $stmt = $pdo->prepare('INSERT INTO paletes (endereco_id) VALUES (:endereco_id)');
        $stmt->execute(['endereco_id' => $enderecoId]);
    }

    echo "Paletes distribuídos com sucesso.";
}

// Chama a função
distribuirPaletes($pdo, 100);
?>
```

### Explicação do Código

1. **Conexão com o Banco de Dados**: Usamos PDO para se conectar ao banco de dados e definir o modo de erro.
2. **Função `distribuirPaletes`**:
   - **Obtém os Endereços**: Seleciona todos os IDs dos endereços disponíveis.
   - **Distribui os Paletes**: Atribui cada palete a um endereço, distribuindo-os de maneira circular. Se houver mais paletes do que endereços, eles serão atribuídos novamente a partir do primeiro endereço.

### Observações

- **Validação e Controle de Erros**: Para um sistema mais robusto, você deve adicionar validação e tratamento de erros mais detalhados.
- **Interface de Usuário**: Este exemplo não inclui uma interface de usuário. Em um sistema real, você pode querer adicionar um front-end para inserir endereços e visualizar a distribuição dos paletes.
- **Escalabilidade**: Para sistemas maiores, considere técnicas mais avançadas de distribuição e gerenciamento de dados.

Esse é um exemplo básico e pode ser expandido com mais funcionalidades conforme necessário. Se você precisar de mais detalhes ou personalizações, sinta-se à vontade para perguntar!
