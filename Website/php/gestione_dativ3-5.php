<?php 

$macaddr = htmlspecialchars($_GET["macaddr"]);	
$delta_reali = htmlspecialchars($_GET["delta_reali"]); 
$delta_random = htmlspecialchars($_GET["delta_random"]); 
$now_reali = htmlspecialchars($_GET["now_reali"]); 
$now_random = htmlspecialchars($_GET["now_random"]);
$time = htmlspecialchars($_GET["time"]);	
$macaddr = explode(",",$macaddr);
$delta_reali = explode(",",$delta_reali);
$delta_random = explode(",",$delta_random);
$now_reali = explode(",",$now_reali);
$now_random = explode(",",$now_random);
$time = explode(",",$time);

echo "delta_random array= ".$delta_random."<br>";

$id = htmlspecialchars($_GET["Id"]);

$reali = htmlspecialchars($_GET["numReali"]); 
$random = htmlspecialchars($_GET["numRandom"]);

$conn = mysqli_connect("localhost", "sniffer5terre","","my_sniffer5terre"); 
if (mysqli_connect_errno($conn)) { 
	echo mysqli_connect_error();
	echo "Failed to connect to database"; 
}
for($i=0;$i<count($macaddr);$i++){
	$nr=(int)$now_reali[$i];
	$nran=(int)$now_random[$i];
	$t=$time[$i];
	$dr=(int)$delta_reali[$i];
	$dran=(int)$delta_random[$i];
	$m=$macaddr[$i];
	$result = mysqli_query($conn, "INSERT INTO `logv3`(`Id`, `Mac_reali`, `Mac_random` , `Timestamp` , `delta_reali` , `delta_random` , `macaddr`) VALUES ('".$id."','".$nr."','".$nran."','".$t."','".$dr."','".$dran."','".$m."')") or die(mysqli_error($conn));
	
	echo mysqli_affected_rows($conn); 
}
	
$result = mysqli_query($conn, "INSERT INTO `log`(`Id`, `Mac_reali`, `Mac_random`) VALUES ('".$id."','".$reali."','".$random."')"); 
echo mysqli_affected_rows($conn); 

?>

