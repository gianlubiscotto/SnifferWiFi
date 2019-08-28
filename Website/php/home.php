<?php
  session_start();
	include "Connessione.php";
  if(isset($_SESSION['login']) and $_SESSION['login']==true and isset($_SESSION['user'])){
    $user=$_SESSION['user'];
  }
  else{
    header("Location: index.php?errore=Non hai i permessi per visualizzare la pagina.");
  }
?>
<!DOCTYPE HTML>
<html>
  <head>
    <title>Console Sniffer5Terre</title>
    <link rel="stylesheet" type="text/css" href="../css/home.css?ts=<?=time()?>&quot"/>
    <link rel="stylesheet" type="text/css" href="../assets/ol3/css/ol.css?ts=<?=time()?>&quot"/>
    <link rel="stylesheet" type="text/css" href="../assets/css/samples.css?ts=<?=time()?>&quot"/>
    <script src="https://code.jquery.com/jquery-2.2.3.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
    <script src="http://www.openlayers.org/api/OpenLayers.js"></script>
    <script src="../assets/ol3/js/ol.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.10/lodash.min.js"></script>
    <script type="text/javascript" src="https://cdn.fusioncharts.com/fusioncharts/latest/fusioncharts.js"></script>
    <script type="text/javascript" src="https://cdn.fusioncharts.com/fusioncharts/latest/themes/fusioncharts.theme.fusion.js"></script>
    <script type="text/javascript" src="https://cdn.fusioncharts.com/fusioncharts/latest/themes/fusioncharts.theme.gammel.js"></script>
    <script type="text/javascript" src="https://cdn.fusioncharts.com/fusioncharts/latest/themes/fusioncharts.theme.candy.js"></script>
    <script type="text/javascript" src="https://rawgit.com/fusioncharts/fusioncharts-jquery-plugin/develop/dist/fusioncharts.jqueryplugin.min.js"></script>
  </head>
  <header>
    <ul>
      <li><a class="sniffertitle">Sniffer5Terre</a></li>
      <li style="float:right"><a class="logout" href="logout.php">Logout</a></li>
      <li style="float:right"><a>Ciao <?php echo $user; ?></a></li>
    </ul>
  </header>
  <body onload="myFunction()">
    <div class="box">
      <label class="title">Mappa in tempo reale	:</label>
      <div class="checkmap">
        <form name="viewmap" class="viewmap" id="viewmap">
          <input name="submit" onclick="riposiziona(Monterosso)" class="b5" type="button" value="Monterosso">
          <input name="submit" onclick="riposiziona(Vernazza)" class="b5" type="button" value="Vernazza">
          <input name="submit" onclick="riposiziona(Corniglia)" class="b5" type="button" value="Corniglia">
          <input name="submit" onclick="riposiziona(Manarola)" class="b5" type="button" value="Manarola">
          <input name="submit" onclick="riposiziona(Riomaggiore)" class="b5" type="button" value="Riomaggiore">
        </form>
        <div id="map" class="map">
          <div id="popup" class="ol-popup">
            <a href="#" id="popup-closer" class="ol-popup-closer"></a>
            <div id="popup-content"></div>
          </div>
          <script>
            // Declare a Tile layer with an OSM source
            var osmLayer = new ol.layer.Tile({
              source: new ol.source.OSM()
            });
            
            // Create latitude and longitude and convert them to default projection
            var Monterosso = ol.proj.transform([9.654885,44.145503], 'EPSG:4326', 'EPSG:3857');
            var Vernazza = ol.proj.transform([9.683089,44.134839], 'EPSG:4326', 'EPSG:3857');
            var Corniglia = ol.proj.transform([9.708366,44.119807], 'EPSG:4326', 'EPSG:3857');
            var Manarola = ol.proj.transform([9.729187,44.105293], 'EPSG:4326', 'EPSG:3857');
            var Riomaggiore = ol.proj.transform([9.738631,44.099424], 'EPSG:4326', 'EPSG:3857');
            var CinqueTerre = ol.proj.transform([9.699685,44.116034], 'EPSG:4326', 'EPSG:3857');
            
            // Create a View, set it center and zoom level
            var view = new ol.View({
              center: CinqueTerre,
              zoom: 12
            });
            
            // Instanciate a Map, set the object target to the map DOM id
            var map = new ol.Map({
              target: 'map'
            });
            
            // Add the created layer to the Map
            map.addLayer(osmLayer);
            
            var Features = [];
            var vectorSource = new ol.source.Vector({
                        features: Features //add an array of features
                    });
            var vectorLayer;
            
            var greenStyle = new ol.style.Style({
              image: new ol.style.Circle({
                radius: 15,
                fill: new ol.style.Fill({color: 'rgba(0,255,0,0.5)'}),
                stroke: new ol.style.Stroke({
                    color: 'green', width: 1
                })
              })
            });
            var yellowStyle = new ol.style.Style({
              image: new ol.style.Circle({
                radius: 15,
                fill: new ol.style.Fill({color: 'rgba(255,255,0,0.5)'}),
                stroke: new ol.style.Stroke({
                    color: 'yellow', width: 1
                })
              })
            });
            var redStyle = new ol.style.Style({
              image: new ol.style.Circle({
                radius: 15,
                fill: new ol.style.Fill({color: 'rgba(255,0,0,0.5)'}),
                stroke: new ol.style.Stroke({
                    color: 'red', width: 1
                })
              })
            });
            var iconStyle = new ol.style.Style({
              image: new ol.style.Icon(/** @type {olx.style.IconOptions} */ ({
                anchor: [0.5,0.5],
                anchorXUnits: 'fraction',
                anchorYUnits: 'fraction',
                opacity: 1,
                src: '../immagini/raspimarker2.png',
                scale: 0.07
              }))
            });
            
            var colors=Array();
            colors[0]=greenStyle;
            colors[1]=yellowStyle;
            colors[2]=redStyle;
            
						//check if page is loaded for the first time
            var first_time=true;
            //check if user clicked any marker
						var click = false;
            var scatolotti="";
            //Array containing the colors of all sniffers. If at least one color changes map needs to be updated
						var oldcolors="";
						
            //Ajax request & on success check if map features need to be updated
						function update(){
            	console.log("2");
							$.ajax({
								url: 'sensors_locations.php',
                type: 'POST',
								async: false,
                dataType : 'json',
                success: function(r){
                  var newcolors=[];
                  //Limit until green
									var limit1;
									//Limit until yellow
                  var limit2;
                  for(var i=0;i<r.length;i++){
                      var id = r[i]["Sensor_id"];
                      var people = parseInt(r[i]["tot"]);
											limit1=parseInt(r[i]["limit1"]);
											limit2=parseInt(r[i]["limit2"]);
											console.log(limit1+" "+limit2);
                      if(people<limit1){
												//Set color to green
												r[i]["color"]=0;
                      }
                      else if(people<limit2){
												//Set color to yellow
                        r[i]["color"]=1;
                      }
											else {
												//Set color to red
												r[i]["color"]=2;
											}
									}
									for(var i=0;i<r.length;i++){
										newcolors.push(r[i]["color"]);
									}
								
									if(first_time){
										//Update called for the first time when the page is loaded
										scatolotti=r;
										oldcolors=newcolors;
										stampaMappa(scatolotti);
										first_time=false;
									}
									else {
										//Update called by setTimeout or by clicking on a marker
										if(!_.isEqual(newcolors,oldcolors)){
											//Some color changed
											scatolotti=r;
											oldcolors=newcolors;
											stampaMappa(scatolotti);   
										}
										else{
											//No color changed
											if(click){
												//Update called by clicking a marker
												click=false;
												scatolotti=r;
												oldcolors=newcolors;
												stampaMappa(scatolotti);
												//if(callback) callback(feature);
											}
										}
									}
								}
							})
            }
            
            //Periodically checking for updates
						function myFunction(){
              update();
              setTimeout(function (){myFunction();},10000);
            }
            
            //Update features' attributes
						function stampaMappa(r){
              vectorSource.clear();
              Features = [];
              for(var i=0;i<r.length;i++){    
								var id = r[i]["Sensor_id"];
								var people = r[i]["tot"];
								var index_color = r[i]["color"];
								var sniffer_name = r[i]["Pseudonimo"];
								var lon = parseFloat(r[i]["Sensor_longitude"]);
								var lat = parseFloat(r[i]["Sensor_latitude"]);
								var ts = r[i]["Timestamp"];
								var chart = r[i]["chartdata"];

								var areaFeature = new ol.Feature({
										geometry: new ol.geom.Point(ol.proj.transform([lon,lat], 'EPSG:4326', 'EPSG:3857')),
											name: sniffer_name,
												tourists: people,
												hour: ts,
												chart: chart
								});
								var iconFeature = new ol.Feature({
										 geometry: new ol.geom.Point(ol.proj.transform([lon,lat], 'EPSG:4326', 'EPSG:3857')),
											name: sniffer_name,
												tourists: people,
												hour: ts,
												chart: chart

								});
								
								if(!first_time){
									var newZoom = map.getView().getZoom();
									var greenStyle = new ol.style.Style({
										image: new ol.style.Circle({
											radius: Math.pow(50,newZoom/5.5)/8000,
											fill: new ol.style.Fill({color: 'rgba(0,255,0,0.5)'}),
											stroke: new ol.style.Stroke({
												color: 'green', width: 1
											})
										})
									});
									var yellowStyle = new ol.style.Style({
										image: new ol.style.Circle({
											radius: Math.pow(50,newZoom/5.5)/8000,
											fill: new ol.style.Fill({color: 'rgba(255,255,0,0.5)'}),
											stroke: new ol.style.Stroke({
												color: 'yellow', width: 1
											})
										})
									});
									var redStyle = new ol.style.Style({
										image: new ol.style.Circle({
											radius: Math.pow(50,newZoom/5.5)/8000,
											fill: new ol.style.Fill({color: 'rgba(255,0,0,0.5)'}),
											stroke: new ol.style.Stroke({
												color: 'red', width: 1
											})
										})
									});
									
									colors[0]=greenStyle;
									colors[1]=yellowStyle;
									colors[2]=redStyle;

									iconFeature.setStyle(iconStyle);
									areaFeature.setStyle(colors[index_color]);
								}
								else{
									iconFeature.setStyle(iconStyle);
									areaFeature.setStyle(colors[index_color]);
								}

								Features.push(areaFeature);
								Features.push(iconFeature);
                    
              }
              if(first_time){
								vectorSource = new ol.source.Vector({
                	features: Features //add an array of features
                });
            
								vectorLayer = new ol.layer.Vector({
                	name:"test",
                  source: vectorSource
                });
                map.addLayer(vectorLayer);
								// Set the view for the map
								map.setView(view);
              }
              else{
                vectorSource.addFeatures(Features);
              }
           	}
           	  
						//Feature click handler
						map.on('click', function(evt) {
							var feature = map.forEachFeatureAtPixel(evt.pixel,
																											function(feature) {
								return feature;
							});
              if (feature) {
								click=true;
								var revenue = FusionCharts("popupchart");
								if(revenue){
									revenue.dispose();
								}
								update();
								//update(showpopup,feature);
								showpopup(feature);
               }
             });
						
            var container = document.getElementById('popup');
            var content = document.getElementById('popup-content');
            var closer = document.getElementById('popup-closer');
            var popup = new ol.Overlay({
              element: container,
              positioning: 'bottom-center',
              stopEvent: true,
              autoPan: true,
              autoPanAnimation: {
                duration: 250
              },
              offset: [0, -20]
            });    
            map.addOverlay(popup);
            
						//Show popup and chart
						function showpopup(feature){
							var coordinates = feature.getGeometry().getCoordinates();
							popup.setPosition(coordinates);
							content.innerHTML = '\
							<div>\
							<div class="popup-titolo">\
							<label id="titolo"></label>\
							</div>\
							<div class="popup-contenuto">\
							<label>Numero di turisti presenti: <label id="turisti"></label></label><br>\
							<label>Ultimo aggiornamento: <label id="orario"></label>\
							<div id="chart-container"></div>\
							</div>\
							</div>';
							document.getElementById('titolo').innerHTML = feature.get('name');
							document.getElementById('turisti').innerHTML = feature.get('tourists');
							document.getElementById('orario').innerHTML = feature.get('hour');
							var chart = feature.get("chart");
							
							var category = "[";
							var totale = "[";
							var random = "[";
							for(var i=0;i<chart.length;i++){
								if(category!="[" && totale!="[" && random!="["){
									category=category+",";
									totale=totale+",";
									random=random+",";
								}
								category=category+"{\"label\":\""+chart[i]["label"]+"\"}";
								totale=totale+"{\"value\":\""+chart[i]["value"]+"\"}";
								random=random+"{\"value\":\""+chart[i]["random"]+"\"}";
							}
							category=category+"]";
							totale=totale+"]";
							random=random+"]";
							
							if(category=="[]"){
								document.getElementById('chart-container').innerHTML = "Nessun dato disponibile nell'ultima ora";
							}	
							else{
								category=JSON.parse(category);
								totale=JSON.parse(totale);
								random=JSON.parse(random);
								//$('document').ready(function () {
									FusionCharts.ready(function() {
										var revenueChart = new FusionCharts({
											type: "scrollcombi2d",
											width: "750",
											height: "300",
											dataFormat: "json",
											id: "popupchart",
											renderAt:"chart-container",
											dataSource: {
												"chart": {
													"caption": "Storico turisti rilevati",
													"xAxisName": "Orario",
													"yAxisName": "Turisti",
													"showvalues": "0",
													"scrollToEnd":"1",
													"numvisibleplot": "7",
													"plottooltext":"<b>$dataValue</b> persone rilevate in data $label",
													"theme":"gammel"
												},
												"categories": [
													{
														"category": category
													}
												],
												"dataset": [
													{
														"seriesname": "Totale dispositivi",
														"renderas":"area",
														"data": totale
													},
													{
														"seriesname": "Mac address randomizzati",
														"renderas": "area",
														"data": random
													}
												]
											}
										});
										revenueChart.render();
									//});
								});
							}
            }
						
						//Popup closer handler
						closer.onclick = function() {
                popup.setPosition(undefined);
                closer.blur();
                return false;
              };
            
						//Zoom handler
            var currZoom = map.getView().getZoom();
            map.on('moveend', function(e) {
							var newZoom = map.getView().getZoom();
              if (currZoom != newZoom) {
                currZoom = newZoom;
                vectorSource.clear();
								//access a color from feature feature["g"]["e"]["a"]["a"]
								//access stroke from feature feature["g"]["e"]["b"]["a"]
								//stroke color of style: Style["e"]["a"]["a"]
								//rgba color of style: Style["e"]["b"]["a"]
								//radius of style: Style["e"]["d"]

								var greenStyle = new ol.style.Style({
									image: new ol.style.Circle({
										radius: Math.pow(50,newZoom/5.5)/8000,
										fill: new ol.style.Fill({color: 'rgba(0,255,0,0.5)'}),
										stroke: new ol.style.Stroke({
												color: 'green', width: 1
										})
									})
								});
								var yellowStyle = new ol.style.Style({
									image: new ol.style.Circle({
										radius: Math.pow(50,newZoom/5.5)/8000,
										fill: new ol.style.Fill({color: 'rgba(255,255,0,0.5)'}),
										stroke: new ol.style.Stroke({
												color: 'yellow', width: 1
										})
									})
								});
								var redStyle = new ol.style.Style({
									image: new ol.style.Circle({
										radius: Math.pow(50,newZoom/5.5)/8000,
										fill: new ol.style.Fill({color: 'rgba(255,0,0,0.5)'}),
										stroke: new ol.style.Stroke({
												color: 'red', width: 1
										})
									})
								});

								for(var i=0;i<Features.length;i++){
									var oldcolor = Features[i]["g"]["e"]["a"]["a"];
									if(oldcolor=="green" || oldcolor=="yellow" || oldcolor=="red"){
										if(oldcolor=="green"){
											Features[i].setStyle(greenStyle);
										}
										else if(oldcolor=="yellow"){
											Features[i].setStyle(yellowStyle);
										}
										else{
												Features[i].setStyle(redStyle);
										}
									}
								}
								vectorSource.addFeatures(Features);
							}
						});
             
						//Riposizionamento mappa tramite bottoni
            function riposiziona(location) {
							// bounce by zooming out one level and back in
              var bounce = ol.animation.bounce({
								resolution: map.getView().getResolution() * 5
              });
              // start the pan at the current center of the map
              var pan = ol.animation.pan({
								source: map.getView().getCenter()
              });
              var zoom = ol.animation.zoom({
                resolution: map.getView().getResolution()
              });
              map.beforeRender(bounce);
              map.beforeRender(pan);
              map.beforeRender(zoom);
              map.getView().setCenter(location);
              view.setZoom(19);
              map.setView(view);                        
            }
            
          </script>
        </div>
      </div>
			
			<script>
				//Insert names of sniffer in the dropdown menu
				$(document).ready(function() {
					$("#paese").change(function() {
						document.getElementById("sensore").disabled=false;
        		var val = $(this).val();
						var sensore = document.getElementById("sensore");
						$("#sensore").empty();
						$.ajax({
								url: 'sensors_dropdown_select.php',
                type: 'POST',
								data: {
									paese: val
								},
                dataType : 'json',
                success: function(r){
									var option = document.createElement("option");
									for(var i=0;i<r.length;i++){
										var pseudonimo = r[i]["Pseudonimo"];
										var id = r[i]["Sensor_id"];
										option = document.createElement("option");
										option.text = pseudonimo;
										option.value = id;
										sensore.appendChild(option);
									}
								}
							})
    			});
				});
				
				//Query to populate the recap chart
				function mySubmit(){
					var nome = $("#sensore option:selected").text();
					var id_sensore = $("#sensore").val();		
					var startdate = $("#startdate").val(); 
					var starttime = $("#starttime").val();
					var enddate = $("#enddate").val();
					var endtime = $("#endtime").val();
					console.log(id_sensore+startdate+starttime+enddate+endtime);
					$.ajax({
						url: 'recap-chart.php',
						type: 'GET',
						data: {
							id_sensore: id_sensore,
							startdate: startdate,
							starttime: starttime,
							enddate: enddate,
							endtime: endtime
						},
						dataType : 'json',
						success: function(r){
							var category = "[";
							var totale = "[";
							var random = "[";
							for(var i=0;i<r.length;i++){
								if(category!="[" && totale!="[" && random!="["){
									category=category+",";
									totale=totale+",";
									random=random+",";
								}
								category=category+"{\"label\":\""+r[i]["label"]+"\"}";
								totale=totale+"{\"value\":\""+r[i]["value"]+"\"}";
								random=random+"{\"value\":\""+r[i]["random"]+"\"}";
							}
							category=category+"]";
							totale=totale+"]";
							random=random+"]";
							category=JSON.parse(category);
							totale=JSON.parse(totale);
							random=JSON.parse(random);

							$('document').ready(function () {
								$("#recap-chart").insertFusionCharts({
									type: "zoomline",
									width: "100%",
									height: "50%",
									dataFormat: "json",
									renderAt:"recap-chart",
									dataSource: {
										"chart": {
											"caption": "Dettaglio sensore: "+nome,
											"xAxisName": "Orario",
											"yAxisName": "Turisti",
											"showvalues": "0",
											"scrollToEnd":"1",
											"numvisibleplot": "10",
											"plottooltext":"<b>$dataValue</b> persone rilevate in data $label",
											"theme":"candy"
										},
										"categories": [
											{
												"category": category
											}
										],
										"dataset": [
											{
												"seriesname": "Totale dispositivi",
												"renderas":"area",
												"data": totale
											},
											{
												"seriesname": "Mac address randomizzati",
												"renderas": "area",
												"data": random
											}
										]
									}
								});
							});
            }
					})
				}
			</script>
			
			<label class="title">Resoconto degli Sniffer:</label>
			<div class="recap">
				<form name="recap-form" method="post" action="javascript:mySubmit()">
					<div class="subrecap">
						<select required id="paese" class="b4">
						<option value="" selected disabled hidden>Seleziona una Terra</option>
						<?php 
							$query="SELECT * FROM Sensors_colocation as S GROUP BY S.Paese";
							$res = mysqli_query($conn, $query) or die(mysqli_error($conn));
							if(mysqli_num_rows($res)> 0){
								while($row = mysqli_fetch_assoc($res)){
									$paese = $row['Paese'];
									echo "<option value='$paese'>$paese</option>";
								}
							}
						?>
					</select>
						<select required id="sensore" class="b4" disabled>
						<option value="" selected disabled hidden>Seleziona un sensore</option>
					</select>
					</div>
					<div class="subrecap">
						<label for="startdate" class="etichetta">Inizio:</label>
						<input required id="startdate" type="date" class="b4" name="startdate">
						<input required id="starttime" type="time" class="b4" name="starttime">
						<label for="enddate" class="etichetta">Fine:</label>
						<input required id="enddate" type="date" class="b4" name="enddate">
						<input required id="endtime" type="time" class="b4" name="endtime">
						<input type="submit" class="b4" value="Guarda l'andamento">
					</div>
				</form>
				<div id="recap-chart" class="recap-chart"></div>
			</div>
    </div>
  </body>
  <script src="../js/buttons.js"></script>
</html>