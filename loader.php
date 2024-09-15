<?php
declare(strict_types=1);

// Evita que usuários acessem este arquivo diretamente
if ( ! defined('ABSPATH')) exit('Acesso direto não permitido.');

// Inicia a sessão, verificando se já não está iniciada
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Verifica o modo para debugar
if ( ! defined('DEBUG') || DEBUG === false ) {
    // Esconde todos os erros
    error_reporting(0);
    ini_set("display_errors", '0'); 
} else {
    // Mostra todos os erros
    error_reporting(E_ALL);
    ini_set("display_errors", '1'); 
}

// Funções globais
$globalFunctionsFile = ABSPATH . '/functions/global-functions.php';

if (file_exists($globalFunctionsFile)) {
    require_once $globalFunctionsFile;
} else {
    exit('Erro: Arquivo de funções globais não encontrado.');
}

// Carrega a aplicação
try {
    $tutsup_mvc = new TutsupMVC();
} catch (Exception $e) {
    error_log('Erro ao carregar a aplicação: ' . $e->getMessage(), 0);
    exit('Erro ao carregar a aplicação.');
}
