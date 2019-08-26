<?php 
	$delta_reali = htmlspecialchars($_GET["delta_reali"]); 
	$delta_random = htmlspecialchars($_GET["delta_random"]); 
	$now_reali = htmlspecialchars($_GET["now_reali"]); 
	$now_random = htmlspecialchars($_GET["now_random"]);
	$macaddr = htmlspecialchars($_GET["macaddr"]);	
	$time = htmlspecialchars($_GET["time"]);
	$id = htmlspecialchars($_GET["Id"]);

	$conn = mysqli_connect("localhost", "sniffer5terre","","my_sniffer5terre"); 
	if (mysqli_connect_errno($conn)) { 
		echo "Failed to connect to database"; 
	} 
	$result = mysqli_query($conn, "INSERT INTO `logv3`(`Id`, `Mac_reali`, `Mac_random` , `Timestamp` , `delta_reali` , `delta_random` , `macaddr`) VALUES ('".$id."','".$now_reali."','".$now_random."','".$time."','".$delta_reali."','".$delta_random."','".$macaddr."')")	; 
	echo mysqli_affected_rows($conn); 
?>
