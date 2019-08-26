<?php
	session_start();
	include "Connessione.php";
	if(isset($_SESSION['login']) and $_SESSION['login']==true and isset($_SESSION['user'])){
			$user=$_SESSION['user'];
	}
	else{
			header("Location: index.php?errore=Non hai i permessi per visualizzare la pagina.");
	}

	$data=$_POST["paese"];
	
	$pseudonimi_array = array();
	$query="SELECT * FROM Sensors_colocation WHERE Paese='$data'";
	$res = mysqli_query($conn, $query) or die(mysqli_error($conn));
	if(mysqli_num_rows($res)> 0){
		while($row = mysqli_fetch_assoc($res)){
			array_push($pseudonimi_array,$row);
		}
	}
	echo json_encode($pseudonimi_array);
?>