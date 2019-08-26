<?php 
	$reali = htmlspecialchars($_GET["numReali"]); 
    $random = htmlspecialchars($_GET["numRandom"]);
    $id = htmlspecialchars($_GET["Id"]);
    echo $reali; 
    echo $random; 
    $conn = mysqli_connect("localhost", "sniffer5terre","","my_sniffer5terre"); 
    if (mysqli_connect_errno($conn)) { 
    	echo "Failed to connect to database"; 
    } 
    $result = mysqli_query($conn, "INSERT INTO `log`(`Id`, `Mac_reali`, `Mac_random`) VALUES ('".$id."','".$reali."','".$random."')"); 
    echo mysqli_affected_rows($conn); 
?>