<?php
declare(strict_types=1);

/**
 * Este arquivo não faz nada, apenas inclui os arquivos necessários
 */

// Verifica se o arquivo de configuração existe antes de incluí-lo
if (file_exists('config.php')) {
    require_once 'config.php';
} else {
    // Lidar com o erro de arquivo não encontrado
    error_log('Arquivo config.php não encontrado.', 0);
    exit('Arquivo de configuração não encontrado.');
}
