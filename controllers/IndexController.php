<?php

class IndexController extends MiniEngine_Controller
{
    public function indexAction()
    {
        $this->init_csrf();
        $this->view->app_name = getenv('APP_NAME');
    }

    public function robotsAction()
    {
        header('Content-Type: text/plain');
        echo "#\n";
        return $this->noview();
    }
}
