<?php
    session_start();
    include "Connessione.php";
    if(isset($_SESSION['login']) and $_SESSION['login']==true and isset($_SESSION['user'])){
        $user=$_SESSION['user'];
    }
    else{
        header("Location: index.php?errore=Non hai i permessi per visualizzare la pagina.");
    }
    
    //$locations_array = array();
    $now = date('Y-m-d H:i:s');   
    $hour_ago = date('Y-m-d H:i:s', strtotime($now) - 1 * 3600);
    
    $response="[";
    #$query="SELECT * FROM (SELECT * FROM Sensors_colocation as S JOIN log as L on S.Sensor_id = L.Id ORDER BY S.Sensor_id ASC, L.Timestamp DESC) AS temp GROUP BY temp.Sensor_id";
		$query="SELECT Id, Sensor_id, Mac_reali, Mac_random, Timestamp, Sensor_longitude, Sensor_latitude, Paese, Pseudonimo, limit1,limit2
FROM (SELECT * FROM log AS L JOIN Sensors_colocation AS S ON L.Id = S.Sensor_id) AS temp 
WHERE Timestamp = (SELECT max(Timestamp) from (SELECT * FROM log AS L JOIN Sensors_colocation AS S ON L.Id = S.Sensor_id) as f WHERE f.Id = temp.Id)"
    $res = mysqli_query($conn, $query) or die(mysqli_error($conn));
    if(mysqli_num_rows($res)> 0){
        while($row = mysqli_fetch_assoc($res)){
            
            $id=$row["Sensor_id"];
            $lon=$row["Sensor_longitude"];
            $lat=$row["Sensor_latitude"];
						$name=$row["Pseudonimo"];
						$limit1=$row["limit1"];
						$limit2=$row["limit2"];
            $ts=$row["Timestamp"];
            $reali=$row["Mac_reali"];
            $random=$row["Mac_random"];
            $tot=$reali+$random;
            
            if($response!="["){
                $response=$response.",";
            }
            $response=$response."{\"Sensor_id\":\"$id\",\"Sensor_longitude\":\"$lon\",\"Sensor_latitude\":\"$lat\",\"Timestamp\":\"$ts\",\"tot\":\"$tot\",\"Pseudonimo\":\"$name\",\"limit1\":\"$limit1\",\"limit2\":\"$limit2\",\"chartdata\":";
            
            $arrLabelValueData = array();
            $query2="SELECT * FROM log WHERE Id = '$id' AND Timestamp between '$hour_ago' and '$now' ORDER BY log.Timestamp ASC";
            $result = mysqli_query($conn, $query2) or die(mysqli_error($conn));
            if(mysqli_num_rows($result)> 0){
                while($row2 = mysqli_fetch_assoc($result)){
                
                    array_push($arrLabelValueData, array('label' => $row2["Timestamp"], 'value' => $row2["Mac_reali"]+$row2["Mac_random"],'random' => $row2["Mac_random"]));
                }
            }
            $arrLabelValueData=json_encode($arrLabelValueData);
            $response=$response.$arrLabelValueData."}";
            //echo json_encode($arrLabelValueData);
            
            //array_push($locations_array,$row);
        }
    }
    $response=$response."]";
    echo $response;
    
    //echo json_encode($locations_array);

?>