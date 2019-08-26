<?php
    session_start();
    include "Connessione.php";
    if(isset($_SESSION['login']) and $_SESSION['login']==true and isset($_SESSION['user'])){
        $user=$_SESSION['user'];
    }
    else{
        header("Location: index.php?errore=Non hai i permessi per visualizzare la pagina.");
    }
		
		$id = $_GET["id_sensore"];
		$startdate = $_GET["startdate"];
		$starttime = $_GET["starttime"];
		$enddate = $_GET["enddate"];
		$endtime = $_GET["endtime"];
		$starttime=$starttime.":00";
		$endtime=$endtime.":00";
		
		$start=$startdate." ".$starttime;
		$start = strtotime($start);
		$end=$enddate." ".$endtime;
		$end = strtotime($end);
		
		$startpoint = date('Y-m-d H:i:s',$start);
		$endpoint = date('Y-m-d H:i:s',$end);
		
		$arrLabelValueData = array();
		$query="SELECT * FROM log WHERE Id = '$id' AND Timestamp between '$startpoint' and '$endpoint' ORDER BY log.Timestamp ASC";
    $res = mysqli_query($conn, $query) or die(mysqli_error($conn));
    if(mysqli_num_rows($res)> 0){
        while($row = mysqli_fetch_assoc($res)){
					$tot=$row["Mac_reali"]+$row["Mac_random"];
					array_push($arrLabelValueData, array('label' => $row["Timestamp"], 'value' => $tot,'random' => $row["Mac_random"]));
				}
		}
		echo json_encode($arrLabelValueData);
?>