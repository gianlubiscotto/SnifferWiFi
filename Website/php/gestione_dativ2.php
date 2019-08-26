<?php 
	$reali = htmlspecialchars($_GET["reali"]); 
	$random = htmlspecialchars($_GET["random"]);
	$now_reali = htmlspecialchars($_GET["now_reali"]); 
	$now_random = htmlspecialchars($_GET["now_random"]);
	$macaddr = htmlspecialchars($_GET["macaddr"]);	
	$time = htmlspecialchars($_GET["time"]);
	$id = htmlspecialchars($_GET["Id"]);
	echo $reali; 
	echo $random; 
	$conn = mysqli_connect("localhost", "sniffer5terre","","my_sniffer5terre"); 
	if (mysqli_connect_errno($conn)) { 
		echo "Failed to connect to database"; 
	} 
	$result = mysqli_query($conn, "INSERT INTO `logv2`(`Id`, `Mac_reali`, `Mac_random` , `Timestamp` , `now_reali` , `now_random`, `macaddr`) VALUES ('".$id."','".$reali."','".$random."','".$time."','".$now_reali."','".$now_random."','".$macaddr."')")	; 
	echo mysqli_affected_rows($conn); 
?>
