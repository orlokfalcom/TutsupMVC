<?php
/**
 * Configuração geral
 * Melhoria aplicada: Uso de variáveis de ambiente e reforço de segurança
 */

// Caminho para a raiz
if (!defined('ABSPATH')) {
    define('ABSPATH', realpath(dirname(__FILE__)));
}

// Caminho para a pasta de uploads
if (!defined('UP_ABSPATH')) {
    define('UP_ABSPATH', ABSPATH . '/views/_uploads');
}

// URL da home
if (!defined('HOME_URI')) {
    define('HOME_URI', getenv('HOME_URI') ?: 'http://127.0.0.1/Cursos/crud');
}

// Nome do host da base de dados
if (!defined('HOSTNAME')) {
    define('HOSTNAME', getenv('DB_HOST') ?: 'localhost'); // Carrega do ambiente se disponível
}

// Nome do DB
if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('DB_NAME') ?: 'tutsup');
}

// Usuário do DB
if (!defined('DB_USER')) {
    define('DB_USER', getenv('DB_USER') ?: 'root');
}

// Senha do DB
if (!defined('DB_PASSWORD')) {
    define('DB_PASSWORD', getenv('DB_PASSWORD') ?: ''); // Coloque a senha real no ambiente
}

// Charset da conexão PDO
if (!defined('DB_CHARSET')) {
    define('DB_CHARSET', 'utf8mb4'); // Alterado para utf8mb4 para suportar emojis e outros caracteres especiais
}

// Verifica se está no modo de debug ou produção
if (!defined('DEBUG')) {
    define('DEBUG', getenv('DEBUG_MODE') === 'true' ? true : false);
}

if (DEBUG === false) {
    // Em produção: Esconde erros e envia para logs
    error_reporting(0);
    ini_set("display_errors", '0');
    ini_set("log_errors", '1');
    ini_set("error_log", ABSPATH . '/logs/php_errors.log'); // Certifique-se de que a pasta logs tem permissões de gravação
} else {
    // Em desenvolvimento: Mostra todos os erros
    error_reporting(E_ALL);
    ini_set("display_errors", '1');
}

/**
 * Carrega o loader da aplicação
 * Certifique-se de que o loader.php existe antes de tentar incluí-lo
 */
$loaderFile = ABSPATH . '/loader.php';
if (file_exists($loaderFile)) {
    require_once $loaderFile;
} else {
    exit('Erro: O arquivo loader.php não foi encontrado.');
}
?>
