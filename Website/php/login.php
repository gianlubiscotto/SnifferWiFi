<?php
    session_start();
    include "Connessione.php";

    $username = $_POST['username'];
    $password = $_POST['password'];
    $errore = false; 
    # controllo campi compilati
    if (!$username || !$password) {
        $errore = true;
        echo "Tutti i campi del modulo sono obbligatori! Torna indietro per completare la registrazione.<br>";
    }

      if (!preg_match('/[a-zA-Z0-9]{4,12}$/i',$username)) {
        $errore = true;
        echo "L'username contiene caratteri non ammessi. Torna indietro e modificalo.<br>";    
    }

    if (!preg_match('/[a-zA-Z0-9]{4,12}$/i',$password)) {
        $errore = true;
        echo "La password contiene caratteri non ammessi. Sono ammessi sono lettere e numeri. Dimensione minima 4 caratteri, dimensione massima 12 caratteri. Torna indietro e modificala.<br>";    
    }
    
    if($errore == false){
        $username = trim($username);
        $username = mysqli_real_escape_string($conn,$username);
        $password = trim($password);
        $password = sha1($password);
        $password = mysqli_real_escape_string($conn,$password);
        
        $query_login = "SELECT * FROM Login WHERE Username = '$username' AND Password = '$password'";
        $result = mysqli_query($conn,$query_login) or die("Ops si è verificato un errore");
        $rowcount=mysqli_num_rows($result);
        if($rowcount>0){
            $row = mysqli_fetch_array($result);
            $_SESSION['login']=true;
            $_SESSION['user']=$row['Username'];
            mysqli_close($conn);
            header('Location: home.php');
           
        }     
        else {
            $_SESSION['login']=false;
            mysqli_close($conn);
            header('Location: index.php?errore=Username o password errati.');
        }
        
    }
    mysqli_close($conn);
?>