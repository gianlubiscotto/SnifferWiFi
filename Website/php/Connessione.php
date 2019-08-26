<?php
    $conn = mysqli_connect('localhost','sniffer5terre','','my_sniffer5terre');
    
    if(mysqli_connect_errno($conn)){
        echo "Failed to connect to database: " . "Ops si è verificato un errore";
    }

?>