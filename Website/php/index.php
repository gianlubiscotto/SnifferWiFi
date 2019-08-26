<?php
    session_start();
    if(isset($_SESSION['login']) and $_SESSION['login']==true){
        header('Location: home.php');       
    }
$err='';
    if(isset($_GET['errore'])){
        $err=$_GET['errore'];
    }
?>
<!DOCTYPE HTML>
<html>
    <head>
        <title>Benvenuto in Sniffer5Terre</title>
        <link rel="stylesheet" type="text/css" href="../css/index.css?ts=<?=time()?>&quot"/>
    </head>
    
    <body>
        <div class="container">
            
            <div class="formlog">
                <label class="title">Benvenuto in Sniffer5Terre</label>
                <form name="login_form" action="login.php" method="post">
                    <input class="inputtext" name="username" type="text" placeholder="username" required><br>
                    <input class="inputtext" name="password" type="password" placeholder="password" required><br>
                    <input name="submit" class="b1" type="submit" value="Accedi">
                </form>
            <?php
                echo $err;
            ?>
            </div>
        </div>
    </body>
</html>