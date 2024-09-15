<?php
/**
 * Verifica chaves de arrays
 *
 * Verifica se a chave existe no array e se ela tem algum valor.
 * Obs.: Essa função está no escopo global, pois, vamos precisar muito da mesma.
 *
 * @param array  $array O array
 * @param string|int $key   A chave do array
 * @return mixed|null  O valor da chave do array ou nulo
 */
function chk_array(array $array, $key) {
    // Usa isset diretamente e retorna o valor ou null
    return isset($array[$key]) && !empty($array[$key]) ? $array[$key] : null;
}

/**
 * Função para carregar automaticamente todas as classes padrão
 * Utiliza spl_autoload_register para substituir __autoload() obsoleto.
 * O nome do arquivo deverá ser class-NomeDaClasse.php.
 * Por exemplo: para a classe TutsupMVC, o arquivo será class-TutsupMVC.php
 */
spl_autoload_register(function ($class_name) {
    $file = ABSPATH . '/classes/class-' . $class_name . '.php';
    
    if (!file_exists($file)) {
        require_once ABSPATH . '/includes/404.php';
        return;
    }
    
    // Inclui o arquivo da classe
    require_once $file;
});
// Funções administrativas
function cadastrarFuncionario($nome, $cpf, $cargo) {
    // Código para cadastrar funcionário
    return "Funcionário $nome cadastrado com sucesso!";
}

function editarFuncionario($id, $novosDados) {
    // Código para editar informações do funcionário
    return "Dados do funcionário ID $id atualizados.";
}

function removerFuncionario($id) {
    // Código para remover funcionário
    return "Funcionário ID $id removido com sucesso.";
}

function listarFuncionarios() {
    // Código para listar todos os funcionários
    return "Lista de funcionários";
}

function gerarRelatorioFuncionarios() {
    // Código para gerar relatório de funcionários
    return "Relatório de funcionários gerado.";
}

function cadastrarDepartamento($nome, $descricao) {
    // Código para cadastrar departamento
    return "Departamento $nome cadastrado.";
}

function editarDepartamento($id, $novosDados) {
    // Código para editar departamento
    return "Departamento ID $id atualizado.";
}

function removerDepartamento($id) {
    // Código para remover departamento
    return "Departamento ID $id removido.";
}

function listarDepartamentos() {
    // Código para listar departamentos
    return "Lista de departamentos.";
}

function gerarRelatorioDepartamentos() {
    // Código para gerar relatório de departamentos
    return "Relatório de departamentos gerado.";
}
// Funções financeiras
function registrarPagamento($valor, $data, $descricao) {
    // Código para registrar pagamento
    return "Pagamento de R$$valor registrado.";
}

function registrarRecebimento($valor, $data, $descricao) {
    // Código para registrar recebimento
    return "Recebimento de R$$valor registrado.";
}

function gerarRelatorioFinanceiro($periodo) {
    // Código para gerar relatório financeiro
    return "Relatório financeiro do período $periodo gerado.";
}

function calcularSaldo($entradas, $saidas) {
    // Código para calcular saldo
    $saldo = $entradas - $saidas;
    return "Saldo atual: R$$saldo";
}

function cadastrarContaPagar($descricao, $valor, $vencimento) {
    // Código para cadastrar conta a pagar
    return "Conta $descricao de R$$valor cadastrada.";
}

function cadastrarContaReceber($descricao, $valor, $vencimento) {
    // Código para cadastrar conta a receber
    return "Conta $descricao de R$$valor cadastrada.";
}

function listarContasPagar() {
    // Código para listar contas a pagar
    return "Lista de contas a pagar.";
}

function listarContasReceber() {
    // Código para listar contas a receber
    return "Lista de contas a receber.";
}

function pagarConta($id) {
    // Código para marcar conta como paga
    return "Conta ID $id paga com sucesso.";
}

function receberPagamento($id) {
    // Código para registrar recebimento de pagamento
    return "Pagamento ID $id recebido com sucesso.";
}
// Funções de controle de estoque
function adicionarProdutoEstoque($produto, $quantidade) {
    // Código para adicionar produto ao estoque
    return "Produto $produto adicionado com sucesso. Quantidade: $quantidade.";
}

function removerProdutoEstoque($produto, $quantidade) {
    // Código para remover produto do estoque
    return "Produto $produto removido. Quantidade: $quantidade.";
}

function listarEstoque() {
    // Código para listar o estoque
    return "Lista de produtos em estoque.";
}

function gerarRelatorioEstoque() {
    // Código para gerar relatório de estoque
    return "Relatório de estoque gerado.";
}

function ajustarEstoque($produto, $novaQuantidade) {
    // Código para ajustar quantidade de estoque
    return "Estoque do produto $produto ajustado para $novaQuantidade.";
}

function cadastrarProduto($nome, $descricao, $preco) {
    // Código para cadastrar novo produto
    return "Produto $nome cadastrado.";
}

function editarProduto($id, $novosDados) {
    // Código para editar dados do produto
    return "Produto ID $id atualizado.";
}

function removerProduto($id) {
    // Código para remover produto
    return "Produto ID $id removido do sistema.";
}

function conferirEstoque($produto, $quantidadeAtual) {
    // Código para conferir estoque
    return $quantidadeAtual >= 0 ? "Estoque do produto $produto está OK." : "Estoque do produto $produto precisa de ajuste.";
}

function gerarRelatorioConferenciaEstoque() {
    // Código para gerar relatório de conferência de estoque
    return "Relatório de conferência de estoque gerado.";
}
// Funções de conferência de estoque
function agendarConferenciaEstoque($data) {
    // Código para agendar conferência
    return "Conferência de estoque agendada para $data.";
}

function realizarConferenciaEstoque($produto, $quantidadeEsperada, $quantidadeAtual) {
    // Código para realizar conferência de estoque
    $diferenca = $quantidadeEsperada - $quantidadeAtual;
    return $diferenca === 0 ? "Conferência do produto $produto está correta." : "Diferença de $diferenca unidades no produto $produto.";
}

function listarConferenciasAgendadas() {
    // Código para listar conferências agendadas
    return "Lista de conferências agendadas.";
}

function gerarRelatorioConferencias() {
    // Código para gerar relatório de conferências realizadas
    return "Relatório de conferências gerado.";
}

function registrarAjusteConferencia($produto, $quantidadeCorrigida) {
    // Código para registrar ajustes de conferência
    return "Ajuste no estoque do produto $produto realizado para $quantidadeCorrigida unidades.";
}

function calcularDivergenciaEstoque($quantidadeEsperada, $quantidadeAtual) {
    // Código para calcular divergências no estoque
    return $quantidadeEsperada - $quantidadeAtual;
}

function registrarDivergenciaEstoque($produto, $diferenca) {
    // Código para registrar divergência
    return "Divergência de $diferenca unidades registrada no produto $produto.";
}

function gerarRelatorioDivergencias() {
    // Código para gerar relatório de divergências no estoque
    return "Relatório de divergências gerado.";
}
function validarEntrada($dados) {
    return htmlspecialchars(strip_tags(trim($dados)));
}
function validarEntrada($dados) {
    return htmlspecialchars(strip_tags(trim($dados)));
}
function cadastrarFuncionario($nome, $cpf, $cargo) {
    $nome = validarEntrada($nome);
    $cpf = validarEntrada($cpf);
    $cargo = validarEntrada($cargo);

    // Continue com o processo de cadastro após sanitizar os dados
}
function cadastrarFuncionario($nome, $cpf, $cargo) {
    $nome = validarEntrada($nome);
    $cpf = validarEntrada($cpf);
    $cargo = validarEntrada($cargo);

    $pdo = new PDO("mysql:host=localhost;dbname=tutsup", "root", "");
    $stmt = $pdo->prepare("INSERT INTO funcionarios (nome, cpf, cargo) VALUES (:nome, :cpf, :cargo)");
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':cpf', $cpf);
    $stmt->bindParam(':cargo', $cargo);
    
    if ($stmt->execute()) {
        return "Funcionário cadastrado com sucesso!";
    } else {
        return "Erro ao cadastrar funcionário.";
    }
}
function listarFuncionarios() {
    // Consulta ao banco para listar funcionários
    $funcionarios = array(
        ['nome' => 'João', 'cargo' => 'Gerente'],
        ['nome' => 'Maria', 'cargo' => 'Assistente']
    );
    
    foreach ($funcionarios as $funcionario) {
        echo 'Nome: ' . htmlspecialchars($funcionario['nome']) . ' - Cargo: ' . htmlspecialchars($funcionario['cargo']);
    }
}
function verificarPermissao($nivelNecessario) {
    if (!isset($_SESSION['usuario']) || $_SESSION['nivel'] < $nivelNecessario) {
        exit("Acesso negado!");
    }
}

// Exemplo de uso em uma função
function cadastrarProduto($nome, $descricao, $preco) {
    verificarPermissao(2); // Apenas usuários de nível 2 ou superior podem cadastrar produtos
    
    // Continuação da função
}
function gerarTokenCSRF() {
    if (empty($_SESSION['token_csrf'])) {
        $_SESSION['token_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['token_csrf'];
}

function validarTokenCSRF($token) {
    if (!isset($_SESSION['token_csrf']) || $token !== $_SESSION['token_csrf']) {
        exit('Falha de verificação CSRF');
    }
}

// Exemplo de uso
$tokenCSRF = gerarTokenCSRF();
echo '<input type="hidden" name="csrf_token" value="' . $tokenCSRF . '">';
function cadastrarProduto($nome, $descricao, $preco, $token) {
    validarTokenCSRF($token); // Verifica o token CSRF
    
    // Continuação da função
}
function cadastrarUsuario($nome, $senha) {
    $senhaHash = password_hash($senha, PASSWORD_BCRYPT);

    // Insere o nome e a senha com hash no banco de dados
}

function verificarUsuario($nome, $senha) {
    $stmt = $pdo->prepare("SELECT senha FROM usuarios WHERE nome = :nome");
    $stmt->bindParam(':nome', $nome);
    $stmt->execute();
    $hash = $stmt->fetchColumn();

    if (password_verify($senha, $hash)) {
        echo "Login bem-sucedido";
    } else {
        echo "Senha incorreta";
    }
}
function verificarTentativasLogin($usuario) {
    if ($_SESSION['tentativas_login'] >= 5) {
        exit('Muitas tentativas falhadas. Tente novamente mais tarde.');
    }
    
    // Se a tentativa for bem-sucedida
    $_SESSION['tentativas_login'] = 0;
}

function falhaLogin() {
    $_SESSION['tentativas_login'] = isset($_SESSION['tentativas_login']) ? $_SESSION['tentativas_login'] + 1 : 1;
}
function registrarLog($mensagem) {
    $arquivo = ABSPATH . '/logs/atividade.log';
    $mensagemLog = date('Y-m-d H:i:s') . " - $mensagem" . PHP_EOL;
    
    file_put_contents($arquivo, $mensagemLog, FILE_APPEND);
}

// Exemplo de uso em uma função
function realizarConferenciaEstoque($produto, $quantidadeEsperada, $quantidadeAtual) {
    $diferenca = $quantidadeEsperada - $quantidadeAtual;
    
    registrarLog("Conferência de estoque do produto $produto realizada. Diferença: $diferenca unidades.");
    
    return $diferenca === 0 ? "Conferência OK." : "Ajuste necessário.";
}
/**
 * Sanitiza uma string para evitar injeções e XSS.
 *
 * @param string $data A string a ser sanitizada.
 * @return string A string sanitizada.
 */
function sanitize_input(string $data): string {
    // Remove espaços em branco do início e do fim
    $data = trim($data);
    // Remove barras invertidas
    $data = stripslashes($data);
    // Converte caracteres especiais em entidades HTML
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}
// Exemplo de uso em um formulário de cadastro
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $nome = sanitize_input($_POST['nome']);
    $email = sanitize_input($_POST['email']);
    // Continue com o processamento dos dados
}
// Validação de e-mail
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit('E-mail inválido.');
}

// Validação de número inteiro
$id = $_GET['id'];
if (!filter_var($id, FILTER_VALIDATE_INT)) {
    exit('ID inválido.');
}
/**
 * Insere um novo usuário no banco de dados usando prepared statements.
 *
 * @param PDO $pdo A instância PDO.
 * @param string $nome O nome do usuário.
 * @param string $email O e-mail do usuário.
 * @return bool Sucesso ou falha da operação.
 */
function inserirUsuario(PDO $pdo, string $nome, string $email): bool {
    $sql = "INSERT INTO usuarios (nome, email) VALUES (:nome, :email)";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([':nome' => $nome, ':email' => $email]);
}

// Uso da função
try {
    $pdo = new PDO("mysql:host=" . HOSTNAME . ";dbname=" . DB_NAME, DB_USER, DB_PASSWORD, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $sucesso = inserirUsuario($pdo, $nome, $email);
    if ($sucesso) {
        echo "Usuário inserido com sucesso.";
    }
} catch (PDOException $e) {
    // Log de erro seguro
    error_log("Erro no banco de dados: " . $e->getMessage());
    exit("Erro ao processar a solicitação.");
}
/**
 * Escapa uma string para saída segura no HTML.
 *
 * @param string $data A string a ser escapada.
 * @return string A string escapada.
 */
function escape_output(string $data): string {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}
/**
 * Gera e armazena um token CSRF na sessão.
 *
 * @return string O token gerado.
 */
function gerarTokenCSRF(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    return $token;
}
/**
 * Valida o token CSRF enviado.
 *
 * @param string $token O token enviado pelo formulário.
 * @return bool Se o token é válido ou não.
 */
function validarTokenCSRF(string $token): bool {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token)) {
        // Token válido, remove para evitar reutilização
        unset($_SESSION['csrf_token']);
        return true;
    }
    return false;
}
// processar_formulario.php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $token = $_POST['csrf_token'] ?? '';
    if (!validarTokenCSRF($token)) {
        exit('Erro: Token CSRF inválido.');
    }
    
    // Continue com o processamento seguro dos dados
}
/**
 * Inicia uma sessão com configurações seguras.
 */
function iniciarSessaoSegura() {
    $sessionName = 'sec_session_id';   // Nome personalizado para a sessão
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'; // HTTPS
    $httponly = true; // Impede acesso via JavaScript

    // Configura os parâmetros da sessão
    session_set_cookie_params([
        'lifetime' => 0, // Expira quando o navegador é fechado
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => 'Strict', // Pode ser 'Lax' ou 'None' conforme necessidade
    ]);

    session_name($sessionName);
    session_start();
    session_regenerate_id(true); // Regenera o ID da sessão para evitar fixation
}

// Uso
iniciarSessaoSegura();
/**
 * Realiza o login do usuário e regenera o ID da sessão.
 *
 * @param string $usuario O identificador do usuário.
 */
function loginUsuario(string $usuario) {
    iniciarSessaoSegura();
    $_SESSION['usuario'] = $usuario;
    session_regenerate_id(true); // Regenera para prevenir fixation
}
/**
 * Verifica se a sessão expirou.
 *
 * @param int $tempoMaximo Tempo máximo de inatividade em segundos.
 * @return bool Se a sessão expirou ou não.
 */
function verificarExpiracaoSessao(int $tempoMaximo = 1800): bool { // 30 minutos
    if (isset($_SESSION['ultimo_acesso'])) {
        if (time() - $_SESSION['ultimo_acesso'] > $tempoMaximo) {
            session_unset();
            session_destroy();
            return true;
        }
    }
    $_SESSION['ultimo_acesso'] = time();
    return false;
}

/**
 * Inclui um arquivo de forma segura.
 *
 * @param string $diretorio Diretório base.
 * @param string $arquivo Nome do arquivo a ser incluído.
 */
function incluirArquivoSegura(string $diretorio, string $arquivo) {
    // Lista branca de arquivos permitidos
    $arquivosPermitidos = ['home.php', 'dashboard.php', 'profile.php'];
    
    if (!in_array($arquivo, $arquivosPermitidos, true)) {
        http_response_code(404);
        include ABSPATH . '/includes/404.php';
        exit();
    }
    
    $caminhoCompleto = realpath($diretorio . '/' . $arquivo);
    
    // Verifica se o caminho está dentro do diretório permitido
    if ($caminhoCompleto && strpos($caminhoCompleto, realpath($diretorio)) === 0) {
        require_once $caminhoCompleto;
    } else {
        http_response_code(404);
        include ABSPATH . '/includes/404.php';
        exit();
    }
}

// Uso
incluirArquivoSegura(ABSPATH . '/includes', $_GET['page'] ?? 'home.php');
/**
 * Força o uso de HTTPS.
 */
function forcarHTTPS() {
    if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
        $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        header('Location: ' . $redirect);
        exit();
    }
}

// Uso
forcarHTTPS();
/**
 * Configura cabeçalhos de segurança HTTP.
 */
function configurarCabecalhosSeguranca() {
    // Previne Clickjacking
    header('X-Frame-Options: SAMEORIGIN');
    
    // Previne sniffing de MIME
    header('X-Content-Type-Options: nosniff');
    
    // Previne ataques XSS
    header('X-XSS-Protection: 1; mode=block');
    
    // Content Security Policy
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';");
    
    // Strict-Transport-Security
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Uso
configurarCabecalhosSeguranca();
