<?php
/**
 * HomeController - Controlador da página inicial
 *
 * @package TutsupMVC
 * @since 0.1
 */
class HomeController extends MainController
{
    /**
     * Carrega a página "/views/home/index.php"
     */
    public function index() {
        // Título da página
        $this->title = 'Home';
        
        // Parâmetros da função
        $parametros = ( func_num_args() >= 1 ) ? func_get_arg(0) : array();

        // Validação básica de parâmetros (se necessário)
        if (!empty($parametros) && is_array($parametros)) {
            // Exemplo de manipulação de parâmetros
        }
    
        /** Verificação de existência dos arquivos **/
        if (file_exists(ABSPATH . '/views/_includes/header.php')) {
            require ABSPATH . '/views/_includes/header.php';
        } else {
            die('Arquivo header.php não encontrado!');
        }

        if (file_exists(ABSPATH . '/views/_includes/menu.php')) {
            require ABSPATH . '/views/_includes/menu.php';
        } else {
            die('Arquivo menu.php não encontrado!');
        }

        if (file_exists(ABSPATH . '/views/home/home-view.php')) {
            require ABSPATH . '/views/home/home-view.php';
        } else {
            die('Arquivo home-view.php não encontrado!');
        }

        if (file_exists(ABSPATH . '/views/_includes/footer.php')) {
            require ABSPATH . '/views/_includes/footer.php';
        } else {
            die('Arquivo footer.php não encontrado!');
        }
        
    } // index
} // class HomeController
